import * as util from 'node:util';
import { assert } from "https://deno.land";
import pack from '../package.json' assert { type: 'json' };

export const version = "" + pack.name + " v" + pack.version;

export enum LEVEL {
  EVERYTHING,
  DEBUG,
  INFO,
  WARN,
  ERROR
}

let _logging_level : LEVEL = LEVEL.INFO;

export function config(level: LEVEL): void {
   _logging_level = level;
};

/**
 * 打印客户端帮助
 */
function printLocalHelp(): void {
  return console.log("usage: sslocal [-h] -s SERVER_ADDR -p SERVER_PORT [-b LOCAL_ADDR] -l LOCAL_PORT -k PASSWORD -m METHOD [-t TIMEOUT] [-c config]\n\noptional arguments:\n  -h, --help            show this help message and exit\n  -s SERVER_ADDR        server address\n  -p SERVER_PORT        server port\n  -b LOCAL_ADDR         local binding address, default is 127.0.0.1\n  -l LOCAL_PORT         local port\n  -k PASSWORD           password\n  -m METHOD             encryption method, for example, aes-256-cfb\n  -t TIMEOUT            timeout in seconds\n  -c CONFIG             path to config file");
}

/**
 * 打印服务器帮助
 */
function printServerHelp(): void {
  return console.log("usage: ssserver [-h] -s SERVER_ADDR -p SERVER_PORT -k PASSWORD -m METHOD [-t TIMEOUT] [-c config]\n\noptional arguments:\n  -h, --help            show this help message and exit\n  -s SERVER_ADDR        server address\n  -p SERVER_PORT        server port\n  -k PASSWORD           password\n  -m METHOD             encryption method, for example, aes-256-cfb\n  -t TIMEOUT            timeout in seconds\n  -c CONFIG             path to config file");
}

interface CommandParams {
  local_address?: string;
  local_port?: number;
  server?: string;
  server_port?: number;
  password?: string;
  config_file?: string;
  method?: string;
  timeout?: number;
};

export function parseArgs(isServer: boolean = null): CommandParams {
  let lastKey: string,
    nextIsValue: boolean,
    oneArg: number | string;
  const result: CommandParams = {};

  if (isServer == null) {
    isServer = false; // 是否是服务器端
  }

  const defination = {
    '-l': 'local_port',
    '-p': 'server_port',
    '-s': 'server',
    '-k': 'password',
    '-c': 'config_file',
    '-m': 'method',
    '-b': 'local_address',
    '-t': 'timeout'
  };

  nextIsValue = false;
  lastKey = null;
  for (const paramKey in process.argv) {
    oneArg = process.argv[paramKey];
    if (nextIsValue) {
      result[lastKey] = oneArg;
      nextIsValue = false;
    } else if (oneArg in defination) { // 存在值的参数
      lastKey = defination[oneArg];
      nextIsValue = true;
    } else if ('-v' === oneArg) {
      result['verbose'] = true;
    } else if (oneArg.indexOf('-') === 0) { // 值不能包含 -
      if (isServer) {
        printServerHelp();
      } else {
        printLocalHelp();
      }
      // 2：表示不正确的命令行参数或其他具体错误。具体含义取决于应用的设计
      process.exit(2);
    }
  }
  return result;
}

export function checkConfig(config): void {
  if (config.server === '127.0.0.1' || config.server === 'localhost') {
    warn("Server is set to " + config.server + ", maybe it's not correct");
    warn("Notice server will listen at " + config.server + ":" + config.server_port);
  }
  if ((config.method || '').toLowerCase() === 'rc4') {
    warn('RC4 is not safe; please use a safer cipher, like AES-256-CFB');
  }
};

export function log(level : LEVEL, msg): void {
  if (level >= _logging_level) {
    if (level >= LEVEL.DEBUG) {
      util.log(new Date().getMilliseconds() + 'ms ' + msg);
    } else {
      util.log(msg);
    }
  }
};

export function debug(msg): void {
  log(LEVEL.DEBUG, msg);
};

export function info(msg): void {
  log(LEVEL.INFO, msg);
};

export function warn(msg): void {
  log(LEVEL.WARN, msg);
};

export function error(msg): void {
  // 如果 msg 是一个错误对象，通常会有一个 stack 属性，包含错误的堆栈跟踪信息。
  // 如果 msg 不是一个错误对象，或者是 null，则返回 undefined（使用 void 0）。
  // 如果前面的表达式（即 msg.stack 或 undefined）为假（即 undefined），则返回 msg 本身。这意味着如果 msg 不是一个错误对象（没有 stack 属性），它将直接返回 msg。
  log(LEVEL.ERROR, (msg != null ? msg.stack : undefined) || msg);
};

export function inetNtoa(buf: Buffer): string {
  return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
};

export function inetAton(ipStr:string): Buffer {
  let buf, i;
  const parts = ipStr.split(".");
  if (parts.length !== 4) {
    return null;
  } else {
    buf = Buffer.alloc(4);
    i = 0;
    while (i < 4) {
      buf[i] = +parts[i];
      i++;
    }
    return buf;
  }
};

setInterval(function() {
  if (_logging_level <= LEVEL.DEBUG) { // 调试模式
    // 调用时，可以传入任何信息，输出到控制台
    debug(JSON.stringify(process.memoryUsage(), null, 2));
    if (global.gc) {
      debug('GC');
      gc(); // 使用 global.gc() 可以请求立即执行垃圾回收
      debug(JSON.stringify(process.memoryUsage(), null, 2));
      const cwd = process.cwd();
      if (_logging_level === LEVEL.DEBUG) {
        try {
          return process.chdir(cwd);
        } catch (_error) {
          return debug(_error);
        }
      }
    }
  }
}, 1000);
