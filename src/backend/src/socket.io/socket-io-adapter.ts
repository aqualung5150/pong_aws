import { INestApplicationContext, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { Namespace, Server, ServerOptions } from 'socket.io';
import { ChatSocket } from './chat/types';
import { GameSocket } from 'src/socket.io/game/types';

export class SocketIOAdapter extends IoAdapter {
    private readonly logger = new Logger(SocketIOAdapter.name);
    constructor(
        private app: INestApplicationContext
    ) {
        super(app);
    }

    createIOServer(port: number, options?: ServerOptions) {
        this.logger.log('웹소켓 서버 생성 - socket.io');

        const jwtService = this.app.get(JwtService);
        const server: Server = super.createIOServer(port, options);

        server.of('chat').use(createJwtMiddleware(jwtService, this.logger));
        server.of('game').use(createGameMiddleware(server.of('game'), jwtService, this.logger));

        return server;
    }
}

const createJwtMiddleware = (jwtService: JwtService, logger: Logger) =>
(socket: ChatSocket | GameSocket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return;
    }
    const nickname = socket.handshake.query.nickname as string;

    try {
        if (!token) {
            throw new Error();
        }
        const payload = jwtService.verify(token, {
            secret: process.env.JWT_ACCESS_TOKEN_SECRET
        });
        socket.userId = payload.id;
        socket.data.id = payload.id;
        socket.email = payload.email;
        socket.nickname = nickname;
        next();
    } catch {
        next(new Error('FORBIDDEN'));
    }
};

const createGameMiddleware = (io: Namespace, jwtService: JwtService, logger: Logger) =>
(socket: ChatSocket | GameSocket, next) => {
    const token = socket.handshake.auth.token;
    const nickname = socket.handshake.query.nickname as string;

    try {
        if (!token) {
            throw new Error();
        }
        const payload = jwtService.verify(token, {
            secret: process.env.JWT_ACCESS_TOKEN_SECRET
        });
        socket.userId = payload.id;
        socket.email = payload.email;
        socket.nickname = nickname;
        // Enforce Only One Connection
        io.sockets.forEach((e: GameSocket) => {
            if (e.userId === socket.userId) {
                logger.warn("you already have connection");
                throw new Error();
            }
        })
        next();
    } catch {
        next(new Error('FORBIDDEN'));
    }
};