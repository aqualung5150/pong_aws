import { createContext } from "react";

export type GameData = {
    // isGameConnected: boolean;
    // roomName: string;
    inGame: boolean;
    gameOver: boolean;
    player: string[];
    playerColor: string[];
    canvasWidth: number;
    canvasHeight: number;
    paddleWidth: number;
    paddleHeight: number;
    ballRadius: number;
    winner: string;
    loser: string;
}

export type GameContent = {
    isGameConnected: boolean;
    matchStartCheck: boolean;
    roomName: string;
    gameData: GameData;
}

export const GameContext = createContext<GameContent>({
    isGameConnected: false,
    matchStartCheck: false,
    roomName: '',
    gameData: {
        // isGameConnected: false,
        // roomName: '',
        inGame: false,
        gameOver: false,
        player: [],
        playerColor: [],
        canvasWidth: 900,
        canvasHeight: 1600,
        paddleWidth: 0,
        paddleHeight: 0,
        ballRadius: 0,
        winner: '',
        loser: '',
    }
})