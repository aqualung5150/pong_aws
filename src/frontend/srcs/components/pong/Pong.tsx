"use client";

import { useRef, useEffect, useContext, useState } from "react";
// import "../pages/index.css";
import { GameContent, GameContext } from "@/context/game";
import { SocketContent, SocketContext } from "@/context/socket";
// import {socket} from "../pages/Home";

export type AutoSave = {
  roomName: string;
  inGame: boolean;
  // inLobby: boolean;
  gameOver: boolean;
  player: string[];
  canvasWidth: number;
  canvasHeight: number;
  paddleWidth: number;
  paddleHeight: number;
  ballRadius: number;
  winner: string;
  loser: string;
};

export type StartGameData = {
  roomName: string;
  player: string[];
  playerColor: string[];
  mode: string;
  canvasWidth: number;
  canvasHeight: number;
  paddleWidth: number;
  paddleHeight: number;
  paddleX: number[];
  ballX: number;
  ballY: number;
  ballRadius: number;
};

export type GameOverData = {
  roomName: string;
  winner: string;
  loser: string;
};

type GameData = {
  roomName: string;
  ballX: number;
  ballY: number;
  paddleX: number[];
  powerUp: boolean[];
  powerBall: boolean;
  playerScore: number[];
};

export default function Pong() {
  const [inGame, setInGame] = useState<boolean>(false);
  const [gameOver, setGameOver] = useState<boolean>(false);

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const socketContext = useContext<SocketContent>(SocketContext);
  const gameContext = useContext<GameContent>(GameContext);
  const gameData = gameContext.gameData;
  const socket: any = socketContext.gameSocket;

  useEffect(() => {
    // Initialize Canvas
    if (!canvasRef.current) {
      return;
    }
    const canvas: HTMLCanvasElement = canvasRef.current;

    const context = canvas.getContext("2d");
    if (!context) {
      return;
    }
    /*-----------------------------------------------------*/
    let interval: ReturnType<typeof setInterval> | undefined;

    let roomName: string = "";
    let winner: string = "";
    let loser: string = "";
    let player: string[] = ["", ""];
    let playerColor: string[] = ["", ""];

    // Power-Up
    let powerUp: boolean[] = [false, false];
    let powerBall: boolean = false;

    // Score
    let score: number[] = [0, 0];

    // Paddle
    let paddleHeight: number = 0;
    let paddleWidth: number = 0;
    let paddleX: number[] = [0, 0];

    // Ball
    let ballX: number = 0;
    let ballY: number = 0;
    let ballRadius: number = 0;

    // Key Event
    const keys = {
      left: {
        pressed: false,
      },
      right: {
        pressed: false,
      },
    };

    roomName = gameContext.roomName;
    setInGame(gameData.inGame);
    setGameOver(gameData.gameOver);
    player = gameData.player;
    playerColor = gameData.playerColor;
    canvas.width = gameData.canvasWidth;
    canvas.height = gameData.canvasHeight;
    paddleWidth = gameData.paddleWidth;
    paddleHeight = gameData.paddleHeight;
    ballRadius = gameData.ballRadius;
    winner = gameData.winner;
    loser = gameData.loser;

    /*-----------------------------------------------------*/

    // Draw
    // Canvas Background
    const drawBackground = () => {
      context.fillStyle = "black";
      context.fillRect(0, 0, canvas.width, canvas.height);
    };

    // Draw Lobby
    const drawLobby = () => {
      canvas.width = 900;
      canvas.height = 1600;
      context.clearRect(0, 0, canvas.width, canvas.height);
      drawBackground();
      context.textAlign = "center";
      context.fillStyle = "white";
      context.font = "140px fantasy";
      context.fillText("PONG", canvas.width / 2, canvas.height * 0.4);
      context.font = "40px monospace";
      context.fillText("← → : MOVE", canvas.width / 2, canvas.height * 0.5);
      context.fillText(
        "SPACE ⎵ : POWER-UP",
        canvas.width / 2,
        canvas.height * 0.5 + 50
      );
    };

    // Draw Game Over
    const drawGameOver = () => {
      context.clearRect(0, 0, canvas.width, canvas.height);
      drawBackground();
      context.textAlign = "center";
      context.fillStyle = "white";
      context.font = "140px fantasy";
      context.fillText("Game Over", canvas.width / 2, canvas.height * 0.4);
      context.font = "40px monospace";
      context.fillText(
        `Winner: ${winner}`,
        canvas.width / 2,
        canvas.height * 0.5
      );
      context.fillText(
        `Loser: ${loser}`,
        canvas.width / 2,
        canvas.height * 0.5 + 50
      );
    };

    let angleA = Math.random() * 360; // start angle (for HSL)
    let angleB = Math.random() * 360;
    let stepA = 3.0,
      stepB = 1.5; // "speed" for change

    function createGradient(x: number, y: number, w: number, h: number) {
      if (!context) {
        return;
      }
      let gr = context.createLinearGradient(0, 0, canvas.width, 0); // create gradient
      gr.addColorStop(0, "hsl(" + (angleA % 360) + ",100%, 50%)"); // start color
      gr.addColorStop(1, "hsl(" + (angleB % 360) + ",100%, 50%)"); // end color
      context.fillStyle = gr; // set as fill style
      context.fillRect(x, y, w, h); // fill area
    }

    // Draw Paddle
    const drawPaddle = () => {
      // Bottom Paddle
      if (powerUp[0]) {
        createGradient(
          paddleX[0],
          canvas.height - 20,
          paddleWidth,
          paddleHeight
        );
      } else {
        context.fillStyle = playerColor[0];
        context.fillRect(
          paddleX[0],
          canvas.height - 20,
          paddleWidth,
          paddleHeight
        );
      }

      // Top Paddle
      if (powerUp[1]) {
        createGradient(paddleX[1], 10, paddleWidth, paddleHeight);
      } else {
        context.fillStyle = playerColor[1];
        context.fillRect(paddleX[1], 10, paddleWidth, paddleHeight);
      }

      angleA += stepA; // increase angles
      angleB += stepB;
    };

    // Draw Ball
    const drawBall = () => {
      context.beginPath();
      context.arc(ballX, ballY, ballRadius, 0, 2 * Math.PI);
      if (powerBall) {
        context.fillStyle = "yellow";
      } else {
        context.fillStyle = "white";
      }
      context.fill();
    };

    // Dashed Center Line
    const drawCenterLine = () => {
      context.beginPath();
      context.setLineDash([4]);
      context.moveTo(0, canvas.height / 2);
      context.lineTo(canvas.width, canvas.height / 2);
      context.strokeStyle = "grey";
      context.stroke();
    };

    // Draw Score
    const drawScore = () => {
      context.textAlign = "left";
      context.font = "120px monospace";
      context.fillStyle = "grey";
      context.fillText(score[1].toString(), 10, canvas.height / 2 - 30);
      context.fillText(score[0].toString(), 10, canvas.height / 2 + 110);
    };

    // Draw All Context
    const draw = () => {
      context.clearRect(0, 0, canvas.width, canvas.height);
      drawBackground();
      drawCenterLine();
      drawScore();
      drawPaddle();
      drawBall();
    };

    /*-----------------------------------------------------*/

    // Lobby
    drawLobby();

    if (inGame) {
      interval = setInterval(() => {
        // Draw Canvas
        draw();
        // Emit Key Event
        if (keys.left.pressed) {
          socket.emit("keydown", {
            roomName: roomName,
            key: "ArrowLeft",
          });
        }

        if (keys.right.pressed) {
          socket.emit("keydown", {
            roomName: roomName,
            key: "ArrowRight",
          });
        }
      }, 15);
    }

    if (gameOver) {
      clearInterval(interval);
      drawGameOver();
    }

    // Listen Key Event - keydown
    const handleKeydown = (e: KeyboardEvent) => {
      switch (e?.key) {
        case "ArrowLeft":
          keys.left.pressed = true;
          break;

        case "ArrowRight":
          keys.right.pressed = true;
          break;
        // powerup
        case " ":
          socket.emit("keydown", {
            roomName: roomName,
            key: " ",
          });
          break;
      }
    };

    const handleKeyup = (e: KeyboardEvent) => {
      switch (e?.key) {
        case "ArrowLeft":
          keys.left.pressed = false;
          break;

        case "ArrowRight":
          keys.right.pressed = false;
          break;
      }
    };

    canvas.addEventListener("keydown", handleKeydown);
    canvas.addEventListener("keyup", handleKeyup);

    // Get Game Data from Server
    socket.on("gameData", (payload: GameData) => {
      ballX = payload.ballX;
      ballY = payload.ballY;
      paddleX = payload.paddleX;
      powerUp = payload.powerUp;
      powerBall = payload.powerBall;
      score = payload.playerScore;
    });

    // clean up
    return () => {
      clearInterval(interval);
      canvas.removeEventListener("keydown", handleKeydown);
      canvas.removeEventListener("keyup", handleKeyup);
    };
  }, [socket, inGame, gameOver, gameData]);

  return (
    <div className={"chat-main"}>
      <canvas className="pong" ref={canvasRef} tabIndex={0} />
    </div>
  );
}
