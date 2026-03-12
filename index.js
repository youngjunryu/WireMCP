// index.js - WireMCP Server (buffer-safe version)
const axios = require('axios');
const { spawn } = require('child_process');
const which = require('which');
const fs = require('fs').promises;
const path = require('path');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

// Never write protocol noise to stdout
console.log = (...args) => console.error(...args);

const EXEC_ENV = process.platform === 'win32'
  ? { env: process.env }
  : {
      env: {
        ...process.env,
        PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
      },
    };

function clampText(text, maxChars = 120000) {
  if (!text) return '';
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n\n[truncated to ${maxChars} chars]`;
}

function buildFrameFilter(startFrame, endFrame) {
  const parts = [];
  if (Number.isFinite(startFrame)) parts.push(`frame.number >= ${startFrame}`);
  if (Number.isFinite(endFrame)) parts.push(`frame.number <= ${endFrame}`);
  return parts.length ? parts.join(' && ') : '';
}

async function ensureFileExists(filePath) {
  await fs.access(filePath);
}

async function findTshark() {
  const envPath = process.env.TSHARK_PATH;
  if (envPath) {
    try {
      await fs.access(envPath);
      console.error(`Found tshark from TSHARK_PATH: ${envPath}`);
      return envPath;
    } catch (e) {
      console.error(`TSHARK_PATH failed: ${e.message}`);
    }
  }

  try {
    const tsharkPath = await which('tshark');
    console.error(`Found tshark at: ${tsharkPath}`);
    return tsharkPath;
  } catch (err) {
    console.error(`which failed to find tshark: ${err.message}`);
  }

  const fallbacks = process.platform === 'win32'
    ? [
        'C:\\Program Files\\Wireshark\\tshark.exe',
        'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
      ]
    : [
        '/usr/bin/tshark',
        '/usr/local/bin/tshark',
        '/opt/homebrew/bin/tshark',
        '/Applications/Wireshark.app/Contents/MacOS/tshark',
      ];

  for (const candidate of fallbacks) {
    try {
      await fs.access(candidate);
      console.error(`Found tshark at fallback: ${candidate}`);
      return candidate;
    } catch (e) {
      console.error(`Fallback ${candidate} not found: ${e.message}`);
    }
  }

  throw new Error(
    'tshark not found. Set TSHARK_PATH or install Wireshark/tshark and add it to PATH.'
  );
}

async function runCommand(cmd, args, options = {}) {
  const {
    cwd,
    env,
    maxStdoutBytes = 8 * 1024 * 1024,
    maxStderrBytes = 2 * 1024 * 1024,
  } = options;

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
    });

    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let killed = false;

    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxStdoutBytes) {
        killed = true;
        child.kill('SIGTERM');
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= maxStderrBytes) {
        stderrChunks.push(chunk);
      }
    });

    child.on('error', (err) => reject(err));

    child.on('close', (code, signal) => {
      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      const stderr = Buffer.concat(stderrChunks).toString('utf8');

      if (killed) {
        return reject(
          new Error(`Command output exceeded limit (${maxStdoutBytes} bytes). Retry with a narrower query.`)
        );
      }

      if (code !== 0) {
        return reject(
          new Error(
            `Command failed with code ${code}${signal ? ` signal ${signal}` : ''}: ${stderr || stdout || 'unknown error'}`
          )
        );
      }

      resolve({ stdout, stderr });
    });
  });
}

async function runTshark(tsharkPath, tsharkArgs, options = {}) {
  return runCommand(tsharkPath, tsharkArgs, {
    env: EXEC_ENV.env,
    ...options,
  });
}

async function fetchURLhausBlacklist() {
  // URLhaus text export can change; keep this tolerant and fail-soft.
  const candidates = [
    'https://urlhaus.abuse.ch/downloads/text_online/',
    'https://urlhaus.abuse.ch/downloads/hostfile/',
  ];

  let lastError;
  for (const url of candidates) {
    try {
      console.error(`Fetching URLhaus data from ${url}`);
      const res = await axios.get(url, { timeout: 15000, responseType: 'text' });
      const lines = String(res.data).split('\n');

      const ips = new Set();
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        const matches = line.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g);
        if (matches) {
          for (const ip of matches) ips.add(ip);
        }
      }

      if (ips.size > 0) {
        console.error(`Fetched ${ips.size} IP indicators from URLhaus`);
        return [...ips];
      }
    } catch (err) {
      lastError = err;
      console.error(`URLhaus fetch failed for ${url}: ${err.message}`);
    }
  }

  throw new Error(`Failed to fetch URLhaus blacklist: ${lastError ? lastError.message : 'unknown error'}`);
}

const server = new McpServer({
  name: 'wiremcp',
  version: '2.0.0',
});

// Tool: capture live packet sample
server.tool(
  'capture_packets',
  'Capture live traffic and return a compact packet sample for analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
    sampleCount: z.number().int().min(1).max(200).optional().default(100).describe('Number of packets to sample'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration, sampleCount } = args;
      const tempPcap = path.join(process.cwd(), `temp_capture_${Date.now()}.pcap`);

      console.error(`Capturing on ${interface} for ${duration}s to ${tempPcap}`);

      await runTshark(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { maxStdoutBytes: 64 * 1024 }
      );

      const { stdout } = await runTshark(
        tsharkPath,
        [
          '-r', tempPcap,
          '-T', 'fields',
          '-E', 'header=y',
          '-E', 'separator=\t',
          '-e', 'frame.number',
          '-e', 'frame.time_epoch',
          '-e', 'ip.src',
          '-e', 'ip.dst',
          '-e', '_ws.col.Protocol',
          '-e', 'tcp.srcport',
          '-e', 'tcp.dstport',
          '-e', 'udp.srcport',
          '-e', 'udp.dstport',
          '-e', '_ws.col.Info',
          '-c', String(sampleCount),
        ],
        { maxStdoutBytes: 1024 * 1024 }
      );

      await fs.unlink(tempPcap).catch((err) => {
        console.error(`Failed to delete ${tempPcap}: ${err.message}`);
      });

      return {
        content: [{
          type: 'text',
          text: `Captured packet sample (${sampleCount} max)\n\n${clampText(stdout, 120000)}`,
        }],
      };
    } catch (error) {
      console.error(`Error in capture_packets: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: summary stats from live capture
server.tool(
  'get_summary_stats',
  'Capture live traffic and provide protocol hierarchy statistics',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = path.join(process.cwd(), `temp_capture_${Date.now()}.pcap`);

      console.error(`Capturing summary stats on ${interface} for ${duration}s`);

      await runTshark(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { maxStdoutBytes: 64 * 1024 }
      );

      const { stdout } = await runTshark(
        tsharkPath,
        ['-r', tempPcap, '-q', '-z', 'io,phs'],
        { maxStdoutBytes: 512 * 1024 }
      );

      await fs.unlink(tempPcap).catch((err) => {
        console.error(`Failed to delete ${tempPcap}: ${err.message}`);
      });

      return {
        content: [{
          type: 'text',
          text: `Protocol hierarchy statistics\n\n${clampText(stdout, 120000)}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_summary_stats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: conversations from live capture
server.tool(
  'get_conversations',
  'Capture live traffic and provide TCP/UDP conversation statistics',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
    protocol: z.enum(['tcp', 'udp']).optional().default('tcp').describe('Conversation protocol'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration, protocol } = args;
      const tempPcap = path.join(process.cwd(), `temp_capture_${Date.now()}.pcap`);

      console.error(`Capturing ${protocol} conversations on ${interface} for ${duration}s`);

      await runTshark(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { maxStdoutBytes: 64 * 1024 }
      );

      const { stdout } = await runTshark(
        tsharkPath,
        ['-r', tempPcap, '-q', '-z', `conv,${protocol}`],
        { maxStdoutBytes: 512 * 1024 }
      );

      await fs.unlink(tempPcap).catch((err) => {
        console.error(`Failed to delete ${tempPcap}: ${err.message}`);
      });

      return {
        content: [{
          type: 'text',
          text: `${protocol.toUpperCase()} conversation statistics\n\n${clampText(stdout, 120000)}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_conversations: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: live capture + threat check
server.tool(
  'check_threats',
  'Capture live traffic and check observed IPs against URLhaus indicators',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = path.join(process.cwd(), `temp_capture_${Date.now()}.pcap`);

      console.error(`Capturing traffic on ${interface} for ${duration}s to check threats`);

      await runTshark(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { maxStdoutBytes: 64 * 1024 }
      );

      const { stdout } = await runTshark(
        tsharkPath,
        ['-r', tempPcap, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'],
        { maxStdoutBytes: 1024 * 1024 }
      );

      const ips = [...new Set(
        stdout
          .split('\n')
          .flatMap((line) => line.split('\t'))
          .map((s) => s.trim())
          .filter((ip) => ip && ip !== 'unknown')
      )];

      console.error(`Captured ${ips.length} unique IPs`);

      let urlhausThreats = [];
      try {
        const urlhausData = await fetchURLhausBlacklist();
        urlhausThreats = ips.filter((ip) => urlhausData.includes(ip));
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
      }

      await fs.unlink(tempPcap).catch((err) => {
        console.error(`Failed to delete ${tempPcap}: ${err.message}`);
      });

      const outputText =
        `Captured IPs (${ips.length})\n` +
        `${ips.length ? ips.join('\n') : 'None'}\n\n` +
        `Threat check against URLhaus\n` +
        `${urlhausThreats.length ? `Potential matches: ${urlhausThreats.join(', ')}` : 'No matches detected.'}`;

      return {
        content: [{ type: 'text', text: clampText(outputText, 120000) }],
      };
    } catch (error) {
      console.error(`Error in check_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: threat check for one IP
server.tool(
  'check_ip_threats',
  'Check a specific IP address against URLhaus indicators',
  {
    ip: z.string().regex(/\b\d{1,3}(?:\.\d{1,3}){3}\b/).describe('IP address to check'),
  },
  async (args) => {
    try {
      const { ip } = args;
      console.error(`Checking IP ${ip} against URLhaus`);

      const urlhausData = await fetchURLhausBlacklist();
      const isThreat = urlhausData.includes(ip);

      return {
        content: [{
          type: 'text',
          text:
            `IP checked: ${ip}\n\n` +
            `Threat check against URLhaus\n` +
            `${isThreat ? 'Potential match detected.' : 'No match detected.'}`,
        }],
      };
    } catch (error) {
      console.error(`Error in check_ip_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: compact pcap overview
server.tool(
  'analyze_pcap',
  'Analyze a PCAP file and provide a compact overview. Does not dump the full packet JSON.',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath } = args;
      console.error(`Analyzing PCAP overview: ${pcapPath}`);

      await ensureFileExists(pcapPath);

      const protocolStats = await runTshark(
        tsharkPath,
        ['-r', pcapPath, '-q', '-z', 'io,phs'],
        { maxStdoutBytes: 512 * 1024 }
      );

      const endpoints = await runTshark(
        tsharkPath,
        ['-r', pcapPath, '-q', '-z', 'endpoints,ip'],
        { maxStdoutBytes: 512 * 1024 }
      ).catch((e) => ({ stdout: `Endpoint stats unavailable: ${e.message}` }));

      const tcpConv = await runTshark(
        tsharkPath,
        ['-r', pcapPath, '-q', '-z', 'conv,tcp'],
        { maxStdoutBytes: 512 * 1024 }
      ).catch((e) => ({ stdout: `TCP conversation stats unavailable: ${e.message}` }));

      const udpConv = await runTshark(
        tsharkPath,
        ['-r', pcapPath, '-q', '-z', 'conv,udp'],
        { maxStdoutBytes: 512 * 1024 }
      ).catch((e) => ({ stdout: `UDP conversation stats unavailable: ${e.message}` }));

      const firstPackets = await runTshark(
        tsharkPath,
        [
          '-r', pcapPath,
          '-T', 'fields',
          '-E', 'header=y',
          '-E', 'separator=\t',
          '-e', 'frame.number',
          '-e', 'frame.time',
          '-e', 'ip.src',
          '-e', 'ip.dst',
          '-e', 'tcp.srcport',
          '-e', 'tcp.dstport',
          '-e', 'udp.srcport',
          '-e', 'udp.dstport',
          '-e', 'frame.protocols',
          '-c', '100',
        ],
        { maxStdoutBytes: 256 * 1024 }
      );

      const outputText =
        `Analyzed PCAP overview: ${pcapPath}\n\n` +
        `=== Protocol Hierarchy ===\n${clampText(protocolStats.stdout, 40000)}\n\n` +
        `=== IP Endpoints ===\n${clampText(endpoints.stdout, 30000)}\n\n` +
        `=== TCP Conversations ===\n${clampText(tcpConv.stdout, 30000)}\n\n` +
        `=== UDP Conversations ===\n${clampText(udpConv.stdout, 30000)}\n\n` +
        `=== First 100 Packets (sample) ===\n${clampText(firstPackets.stdout, 20000)}\n\n` +
        `Use detail/page tools for deeper analysis.`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in analyze_pcap: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: bounded packet page
server.tool(
  'get_packet_page',
  'Read a bounded page of packets from a PCAP file',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    startFrame: z.number().int().min(1).default(1).describe('Start frame number'),
    count: z.number().int().min(1).max(500).default(100).describe('Number of frames to return'),
    displayFilter: z.string().optional().describe('Optional tshark display filter'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, startFrame, count, displayFilter } = args;

      await ensureFileExists(pcapPath);

      const endFrame = startFrame + count - 1;
      const frameFilter = buildFrameFilter(startFrame, endFrame);
      const filters = [frameFilter, displayFilter].filter(Boolean).join(' && ');

      const tsharkArgs = [
        '-r', pcapPath,
        ...(filters ? ['-Y', filters] : []),
        '-T', 'fields',
        '-E', 'header=y',
        '-E', 'separator=\t',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', '_ws.col.Protocol',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', '_ws.col.Info',
      ];

      const { stdout } = await runTshark(tsharkPath, tsharkArgs, {
        maxStdoutBytes: 1024 * 1024,
      });

      return {
        content: [{
          type: 'text',
          text:
            `Packet page from ${pcapPath}\n` +
            `Frame range: ${startFrame}-${endFrame}\n` +
            `Filter: ${filters || '(none)'}\n\n` +
            clampText(stdout, 120000),
        }],
      };
    } catch (error) {
      console.error(`Error in get_packet_page: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: single frame detail
server.tool(
  'get_frame_detail',
  'Get detailed decode for a single frame number from a PCAP file',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    frameNumber: z.number().int().min(1).describe('Frame number to inspect'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, frameNumber } = args;

      await ensureFileExists(pcapPath);

      const { stdout } = await runTshark(
        tsharkPath,
        ['-r', pcapPath, '-Y', `frame.number == ${frameNumber}`, '-T', 'json'],
        { maxStdoutBytes: 1024 * 1024 }
      );

      return {
        content: [{
          type: 'text',
          text: `Detailed frame decode for ${pcapPath}, frame ${frameNumber}\n${clampText(stdout, 120000)}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_frame_detail: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: anomaly finder
server.tool(
  'find_anomalies',
  'Find bounded anomaly packets in a PCAP file using common tshark filters',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    anomalyType: z.enum([
      'retransmission',
      'dup_ack',
      'rst',
      'dns_error',
      'http_error',
      'tls_alert',
      'syn_only',
      'no_response_hint',
    ]).describe('Anomaly type to search for'),
    startFrame: z.number().int().min(1).optional().describe('Optional start frame'),
    endFrame: z.number().int().min(1).optional().describe('Optional end frame'),
    limit: z.number().int().min(1).max(300).default(100).describe('Max packets to return'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, anomalyType, startFrame, endFrame, limit } = args;

      await ensureFileExists(pcapPath);

      const anomalyFilters = {
        retransmission: 'tcp.analysis.retransmission || tcp.analysis.fast_retransmission',
        dup_ack: 'tcp.analysis.duplicate_ack',
        rst: 'tcp.flags.reset == 1',
        dns_error: 'dns.flags.rcode != 0',
        http_error: 'http.response.code >= 400',
        tls_alert: 'tls.alert_message',
        syn_only: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
        no_response_hint: 'tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment',
      };

      const rangeFilter = buildFrameFilter(startFrame, endFrame);
      const filter = [rangeFilter, anomalyFilters[anomalyType]].filter(Boolean).join(' && ');

      const { stdout } = await runTshark(
        tsharkPath,
        [
          '-r', pcapPath,
          '-Y', filter,
          '-T', 'fields',
          '-E', 'header=y',
          '-E', 'separator=\t',
          '-e', 'frame.number',
          '-e', 'frame.time_epoch',
          '-e', 'ip.src',
          '-e', 'ip.dst',
          '-e', '_ws.col.Protocol',
          '-e', '_ws.col.Info',
          '-c', String(limit),
        ],
        { maxStdoutBytes: 1024 * 1024 }
      );

      return {
        content: [{
          type: 'text',
          text:
            `Anomaly search: ${anomalyType}\n` +
            `PCAP: ${pcapPath}\n` +
            `Filter: ${filter}\n` +
            `Limit: ${limit}\n\n` +
            clampText(stdout, 120000),
        }],
      };
    } catch (error) {
      console.error(`Error in find_anomalies: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool: stream packets
server.tool(
  'get_stream_packets',
  'Get packets for a specific TCP stream in bounded pages',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    streamId: z.number().int().min(0).describe('tcp.stream value'),
    startFrame: z.number().int().min(1).optional().describe('Optional start frame'),
    endFrame: z.number().int().min(1).optional().describe('Optional end frame'),
    limit: z.number().int().min(1).max(300).default(200).describe('Max packets to return'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, streamId, startFrame, endFrame, limit } = args;

      await ensureFileExists(pcapPath);

      const rangeFilter = buildFrameFilter(startFrame, endFrame);
      const filter = [`tcp.stream == ${streamId}`, rangeFilter].filter(Boolean).join(' && ');

      const { stdout } = await runTshark(
        tsharkPath,
        [
          '-r', pcapPath,
          '-Y', filter,
          '-T', 'fields',
          '-E', 'header=y',
          '-E', 'separator=\t',
          '-e', 'frame.number',
          '-e', 'frame.time_epoch',
          '-e', 'ip.src',
          '-e', 'tcp.srcport',
          '-e', 'ip.dst',
          '-e', 'tcp.dstport',
          '-e', 'tcp.flags.str',
          '-e', '_ws.col.Info',
          '-c', String(limit),
        ],
        { maxStdoutBytes: 1024 * 1024 }
      );

      return {
        content: [{
          type: 'text',
          text:
            `TCP stream packets\n` +
            `PCAP: ${pcapPath}\n` +
            `Stream: ${streamId}\n` +
            `Filter: ${filter}\n\n` +
            clampText(stdout, 120000),
        }],
      };
    } catch (error) {
      console.error(`Error in get_stream_packets: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Prompts
server.prompt(
  'capture_packets_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
    sampleCount: z.number().optional().describe('Number of packets to sample'),
  },
  ({ interface = 'en0', duration = 5, sampleCount = 100 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please analyze live traffic on interface ${interface} for ${duration} seconds.\n` +
          `Use a bounded sample of up to ${sampleCount} packets and describe:\n` +
          `1. traffic types observed\n` +
          `2. notable patterns or anomalies\n` +
          `3. key IPs and ports involved\n` +
          `4. potential security concerns`,
      },
    }],
  })
);

server.prompt(
  'summary_stats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please summarize network traffic statistics from interface ${interface} over ${duration} seconds, focusing on:\n` +
          `1. protocol distribution\n` +
          `2. traffic volume by protocol\n` +
          `3. notable usage patterns\n` +
          `4. potential network health indicators`,
      },
    }],
  })
);

server.prompt(
  'conversations_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
    protocol: z.enum(['tcp', 'udp']).optional().describe('Conversation protocol'),
  },
  ({ interface = 'en0', duration = 5, protocol = 'tcp' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please analyze ${protocol.toUpperCase()} conversations on interface ${interface} for ${duration} seconds and identify:\n` +
          `1. most active IP pairs\n` +
          `2. conversation durations and data volumes\n` +
          `3. unusual communication patterns\n` +
          `4. potential indicators of network issues`,
      },
    }],
  })
);

server.prompt(
  'check_threats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please analyze traffic on interface ${interface} for ${duration} seconds and check for security concerns:\n` +
          `1. compare captured IPs against URLhaus indicators\n` +
          `2. identify potentially malicious activity\n` +
          `3. highlight concerning patterns\n` +
          `4. provide security recommendations`,
      },
    }],
  })
);

server.prompt(
  'check_ip_threats_prompt',
  {
    ip: z.string().describe('IP address to check'),
  },
  ({ ip }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please analyze the IP address ${ip} for potential security threats:\n` +
          `1. check against URLhaus indicators\n` +
          `2. evaluate threat relevance\n` +
          `3. summarize risk\n` +
          `4. provide security recommendations`,
      },
    }],
  })
);

server.prompt(
  'analyze_pcap_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please analyze the PCAP file at ${pcapPath} and provide a compact overview of:\n` +
          `1. overall traffic patterns\n` +
          `2. key endpoints and interactions\n` +
          `3. protocols and services used\n` +
          `4. notable anomalies\n` +
          `5. suggested next detail queries`,
      },
    }],
  })
);

server.prompt(
  'packet_page_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    startFrame: z.number().optional().describe('Start frame number'),
    count: z.number().optional().describe('Number of frames'),
    displayFilter: z.string().optional().describe('Optional display filter'),
  },
  ({ pcapPath, startFrame = 1, count = 100, displayFilter = '' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please inspect frames ${startFrame}-${startFrame + count - 1} from ${pcapPath}` +
          `${displayFilter ? ` using filter: ${displayFilter}` : ''} and summarize the packet behavior.`,
      },
    }],
  })
);

server.prompt(
  'frame_detail_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    frameNumber: z.number().describe('Frame number'),
  },
  ({ pcapPath, frameNumber }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please inspect frame ${frameNumber} from ${pcapPath} and explain its technical significance.`,
      },
    }],
  })
);

server.prompt(
  'find_anomalies_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    anomalyType: z.string().describe('Anomaly type'),
    startFrame: z.number().optional().describe('Optional start frame'),
    endFrame: z.number().optional().describe('Optional end frame'),
    limit: z.number().optional().describe('Result limit'),
  },
  ({ pcapPath, anomalyType, startFrame, endFrame, limit = 100 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please search ${pcapPath} for anomaly type "${anomalyType}"` +
          `${startFrame ? ` from frame ${startFrame}` : ''}` +
          `${endFrame ? ` to frame ${endFrame}` : ''}` +
          ` with limit ${limit}, and summarize the findings.`,
      },
    }],
  })
);

server.prompt(
  'stream_packets_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    streamId: z.number().describe('TCP stream ID'),
    startFrame: z.number().optional().describe('Optional start frame'),
    endFrame: z.number().optional().describe('Optional end frame'),
    limit: z.number().optional().describe('Result limit'),
  },
  ({ pcapPath, streamId, startFrame, endFrame, limit = 200 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text:
          `Please inspect TCP stream ${streamId} in ${pcapPath}` +
          `${startFrame ? ` from frame ${startFrame}` : ''}` +
          `${endFrame ? ` to frame ${endFrame}` : ''}` +
          ` with limit ${limit}, and summarize the stream behavior.`,
      },
    }],
  })
);

// Start server
server.connect(new StdioServerTransport())
  .then(() => console.error('WireMCP Server is running...'))
  .catch((err) => {
    console.error('Failed to start WireMCP:', err);
    process.exit(1);
  });
