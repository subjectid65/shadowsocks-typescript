import net from 'net';
import fs from 'fs';
import path from 'path';
import * as udpRelay from './udprelay.js';
import * as utils from './utils.js';
import * as inet from './inet.js';
import { Encryptor } from './encrypt.js';

export function main(): void {
  console.log(utils.version);
  const configFromArgs = utils.parseArgs(true);
  let configPath = 'config.json';
   // //if (configFromArgs?.config_file) {
    // // configPath = configFromArgs.config_file;
  // // } else {
  // //   utils.info('no config file found.');
  // //   process.exit(1);
  // // }
  if (!fs.existsSync(configPath)) {
    configPath = path.resolve(__dirname, 'config.json');
    if (!fs.existsSync(configPath)) {
      configPath = path.resolve(__dirname, '../../config.json');
      if (!fs.existsSync(configPath)) {
        configPath = null;
      }
    }
  }
  let configContent;
  let config;
  if (configPath) {
    utils.info('loading config from ' + configPath);
    configContent = fs.readFileSync(configPath);
    try {
      config = JSON.parse(configContent);
    } catch (_error) {
      utils.error('found an error in config.json: ' + _error.message);
      process.exit(1);
    }
  } else {
    config = {};
  }
  for (const k in configFromArgs) {
    const v = configFromArgs[k];
    config[k] = v;
  }
  if (config.verbose) {
    utils.config(utils.LEVEL.DEBUG);
  }

  utils.checkConfig(config);
  const timeout = Math.floor(config.timeout * 1000) || 300000; // 连接超时
  let portPassword = config.port_password; // 端口对应密码
  let port = config.server_port; // 服务器监听端口
  let key = config.password; // 加密密码
  const METHOD = config.method; // 加密方式
  const SERVER = config.server; // 监听地址
  if (!(SERVER && (port || portPassword) && key)) {
    utils.warn(
      'config.json not found, you have to specify all config in commandline',
    );
    process.exit(1);
  }
  const connections = {
    count: 0
  };
  if (portPassword) {
    if (port || key) {
      utils.warn(
        'warning: port_password should not be used with server_port and password. server_port and password will be ignored',
      );
    }
  } else {
    portPassword = {};
    portPassword[port.toString()] = key;
  }
  const _results = [];
  let servers;

  for (port in portPassword) {
    key = portPassword[port]; // 根据端口获取密钥
    servers = SERVER;
    if (!(servers instanceof Array)) {
      servers = [servers];
    }
    _results.push(
      handle_port_password(servers, port, key, connections, timeout, METHOD),
    );
  }
  // return _results;
}

function handle_port_password(
  servers,
  port,
  key,
  connections,
  timeout,
  METHOD,
) {
  const _results1 = [];
  // 服务器端可配置多个服务ip和端口
  let a_server_ip;
  for (let _i = 0, _len = servers.length; _i < _len; _i++) {
    a_server_ip = servers[_i];
    _results1.push(
      handle_muti_server(port, key, a_server_ip, connections, timeout, METHOD),
    );
  }
  return _results1;
}

function handle_muti_server(
  port,
  key,
  a_server_ip,
  connections,
  timeout,
  METHOD,
) {
  const PORT = port;
  const KEY = key;
  const server_ip = a_server_ip;
  utils.info('calculating ciphers for port ' + PORT);
  // 为每一个服务器配置创建服务
  const server = net.createServer(function (connection) {
    connections.count += 1;
    let encryptor = new Encryptor(KEY, METHOD);
    let stage = 0;
    let headerLength = 0;
    let remote = null;
    let cachedPieces = [];
    let addrLen = 0;
    let remoteAddr = null;
    let remotePort = null;
    utils.debug('connections: ' + connections.count);

    const clean = function () {
      utils.debug('clean');
      connections.count -= 1;
      remote = null;
      connection = null;
      encryptor = null;
      return utils.debug('connections: ' + connections.count);
    };

    connection.on('data', function (data) {
      utils.log(utils.LEVEL.EVERYTHING, 'connection on data');
      try {
        data = encryptor.decrypt(data); // 解密数据，包含 [target address][payload]
      } catch (_error) {
        utils.error(_error);
        if (remote) {
          remote.destroy();
        }
        if (connection) {
          connection.destroy();
        }
        return;
      }

      if (stage === 5) {
        if (!remote.write(data)) {
          connection.pause();
        }
        return;
      }
      let addrtype;
      let buf;
      if (stage === 0) {
        try {
          // 开始解析shadowsocks协议头
          addrtype = data[0]; // 获取地址类型
          if (addrtype === void 0) {
            return;
          }
          if (addrtype === 3) {
            // 可变长度的域名
            addrLen = data[1]; // 第一个字节是域名的长度
          } else if (addrtype !== 1 && addrtype !== 4) {
            utils.error(
              'unsupported addrtype: ' + addrtype + ' maybe wrong password',
            );
            connection.destroy();
            return;
          }
          if (addrtype === 1) {
            // ipv4地址
            remoteAddr = utils.inetNtoa(data.slice(1, 5));
            // 用于从 Buffer 中以大端格式读取无符号的 16 位整数，从偏移量 5 开始的两个字节
            remotePort = data.readUInt16BE(5);
            headerLength = 7;
          } else if (addrtype === 4) {
            // ipv6地址
            remoteAddr = inet.inet_ntop(data.slice(1, 17));
            remotePort = data.readUInt16BE(17);
            headerLength = 19;
          } else {
            // 域名地址
            remoteAddr = data.slice(2, 2 + addrLen).toString('binary');
            remotePort = data.readUInt16BE(2 + addrLen);
            headerLength = 2 + addrLen + 2;
          }
          // 此方法用于暂停对连接数据的流式读取。这意味着在调用该方法后，连接将不会再触发 data 事件，直到恢复为止
          connection.pause();
          // 开始连接目标服务器
          remote = net.connect(remotePort, remoteAddr, function () {
            utils.info('connecting ' + remoteAddr + ':' + remotePort);
            if (!encryptor || !remote || !connection) {
              if (remote) {
                remote.destroy();
              }
              return;
            }
            let i = 0;
            // 此方法用于恢复之前暂停的连接数据流。调用该方法后，连接将重新开始接收数据并触发 data 事件
            connection.resume();
            let piece;
            while (i < cachedPieces.length) {
              piece = cachedPieces[i];
              remote.write(piece); // 把缓存数据片发送到远程目标
              i++;
            }
            cachedPieces = null;
            // 设置远程连接超时
            remote.setTimeout(timeout, function () {
              utils.debug('remote on timeout during connect()');
              if (remote) {
                remote.destroy();
              }
              if (connection) {
                connection.destroy();
              }
            });
            stage = 5;
            return utils.debug('stage = 5');
          });

          // 开始监听远程响应
          remote.on('data', function (data) {
            utils.log(utils.LEVEL.EVERYTHING, 'remote on data');
            if (!encryptor) {
              if (remote) {
                remote.destroy();
              }
              return;
            }
            // 加密远程响应的数据
            data = encryptor.encrypt(data);
            if (!connection.write(data)) {
              return remote.pause();
            }
          });

          remote.on('end', function () {
            utils.debug('remote on end');
            if (connection) {
              connection.end();
            }
          });

          remote.on('error', function (e) {
            utils.debug('remote on error');
            utils.error(
              'remote ' + remoteAddr + ':' + remotePort + ' error: ' + e,
            );
          });

          remote.on('close', function (had_error) {
            utils.debug('remote on close:' + had_error);
            if (had_error) {
              if (connection) {
                connection.destroy();
              }
            } else {
              if (connection) {
                connection.end();
              }
            }
          });

          remote.on('drain', function () {
            utils.debug('remote on drain');
            if (connection) {
              connection.resume();
            }
          });

          remote.setTimeout(15 * 1000, function () {
            utils.debug('remote on timeout during connect()');
            if (remote) {
              remote.destroy();
            }
            if (connection) {
              connection.destroy();
            }
          });

          // local发送过来的数据大于 headerLength，说明包含ss协议体内容
          if (data.length > headerLength) {
            buf = Buffer.alloc(data.length - headerLength);
            data.copy(buf, 0, headerLength); // 复制ss协议体内容
            cachedPieces.push(buf);
            buf = null;
          }
          stage = 4;
          return utils.debug('stage = 4');
        } catch (_error) {
          utils.error(_error);
          connection.destroy();
          if (remote) {
            return remote.destroy();
          }
        }
      } else {
        if (stage === 4) {
          return cachedPieces.push(data); // 接下来的数据都是 ss 协议体内容
        }
      }
    });
    connection.on('end', function () {
      utils.debug('connection on end');
      if (remote) {
        return remote.end();
      }
    });
    connection.on('error', function (e) {
      utils.debug('connection on error');
      return utils.error('local error: ' + e);
    });
    connection.on('close', function (had_error) {
      utils.debug('connection on close:' + had_error);
      if (had_error) {
        if (remote) {
          remote.destroy();
        }
      } else {
        if (remote) {
          remote.end();
        }
      }
      return clean();
    });
    connection.on('drain', function () {
      utils.debug('connection on drain');
      if (remote) {
        return remote.resume();
      }
    });
    return connection.setTimeout(timeout, function () {
      utils.debug('connection on timeout');
      if (remote) {
        remote.destroy();
      }
      if (connection) {
        connection.destroy();
      }
    });
  });

  server.listen(PORT, server_ip, function () {
    utils.info('server listening at ' + server_ip + ':' + PORT + ' ');
  });

  udpRelay.createServer(
    server_ip,
    PORT,
    null,
    null,
    key,
    METHOD,
    timeout,
    false,
  );

  return server.on('error', function (e) {
    const error = e as NodeJS.ErrnoException; // 类型断言
    if (error.code === 'EADDRINUSE') {
      utils.error('Address in use, aborting');
    } else {
      utils.error(e);
    }
    return process.stdout.on('drain', function () {
      process.exit(1);
    });
  });
}
