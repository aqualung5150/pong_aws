import { Socket } from "socket.io"
import { Invitation } from "./dto/invitation.dto";

type Player = {
    color: string;
    nickname: string;
    inGame: boolean;
    invitationList: Invitation[];
}

type JwtPayload = {
    userId: number;
    email: string;
}

export type GameRoomParams = {
    name: string;
    player: GameSocket[];
    mode: string;
}

export type GameSocket = Socket & JwtPayload & Player;