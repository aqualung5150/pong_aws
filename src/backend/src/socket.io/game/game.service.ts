import { Injectable } from '@nestjs/common';
import { GameSocket } from './types';
import { GameRoom } from './GameRoom';
import { Namespace } from 'socket.io';
import { ChatUserStoreService, User } from '../store/store.user.service';
import { ChatRoomStoreService, Room } from '../store/store.room.service';

@Injectable()
export class GameService {
  constructor (
    private readonly storeUser : ChatUserStoreService,
    private readonly storeRoom : ChatRoomStoreService
  ){}
  validatePlayerInRoom(
      player: GameSocket,
      gameRoom: GameRoom,
      ) {
      if (!gameRoom) {
          throw new Error('no such room');
        }

      if (player !== gameRoom.player[0] && player !== gameRoom.player[1]) {
          throw new Error(`no such user in the room: ${player.id}`);
      }
  }

  startGame(io: Namespace, room: GameRoom) {
    // Set gameStart
    room.gameStart = true;
    // send game data for Init
      io.to(room.name).emit('startGame', {
      roomName: room.name,
      player: [room.player[0].nickname, room.player[1].nickname],
      playerColor: [room.player[0].color, room.player[1].color],
      mode: room.mode,
      canvasWidth: room.canvasWidth,
      canvasHeight: room.canvasHeight,
      paddleWidth: room.paddleWidth,
      paddleHeight: room.paddleHeight,
      paddleX: room.paddleX,
      ballX: room.ballX,
      ballY: room.ballY,
      ballRadius: room.ballRadius,
    });

    // setInterval
    room.interval = setInterval(() => {
      this.ballMove(room);

      // console.log("Speed X:", room.speedX);

      // send game data for drawing
      io.to(room.name).emit('gameData', {
        roomName: room.name,
        ballX: room.ballX,
        ballY: room.ballY,
        paddleX: room.paddleX,
        powerUp: room.powerUp,
        powerBall: room.powerBall,
        playerScore: room.playerScore,
      });
    }, 15);
  }

  ballMove(room: GameRoom) {
    // Vertical Speed
    if (room.powerBall) {
      room.ballY += (room.maxSpeedY + 3) * room.ballDirection;
    } else {
      room.ballY += room.speedY * room.ballDirection;
    }

    // Horizontal Speed
    room.ballX += room.speedX;
    // Bounce off Left Wall
    if (room.ballX < 0 && room.speedX < 0) {
      room.speedX = -room.speedX;
    }
    // Bounce off Right Wall
    if (room.ballX > room.canvasWidth && room.speedX > 0) {
      room.speedX = -room.speedX;
    }
    
    if (room.ballY > room.canvasHeight - room.paddleDiff) {
      // Bounce off player paddle (bottom)
      if (room.ballX >= room.paddleX[0] && room.ballX <= room.paddleX[0] + room.paddleWidth) {
        // Set ball crood right on paddle
        room.ballY = room.canvasHeight - room.paddleDiff;
        if (room.powerUp[0]) {
          // make ball power-up
          room.powerBall = true;
        } else {
          // turn off power-up ball speed
          room.powerBall = false;
          // Add Speed on Hit
          room.speedY += 1;
          // Max Speed
          if (room.speedY > room.maxSpeedY) {
            room.speedY = room.maxSpeedY;
          }
        }
          
          room.ballDirection = -room.ballDirection;
          room.speedX = room.speedX > 0 ?
            Math.random() * room.maxSpeedX :
            Math.random() * -room.maxSpeedX;
      } else {
        // Add to Computer Score
        room.playerScore[1]++;
        // console.log(room.playerScore);
        // Game Over
        if (room.playerScore[1] >= 3) {
          clearInterval(room.interval);
          room.winner = room.player[1];
          room.loser = room.player[0];
          room.gameOver = true;
          // console.log("-----Game Over-----");
          // console.log("Winner:", room.winner.nickname);
          // console.log("Loser:", room.loser.nickname);
          // console.log("-------Score-------");
          // console.log(`${room.playerScore[0]} - ${room.player[0].nickname}`);
          // console.log(`${room.playerScore[1]} - ${room.player[1].nickname}`);
          return;
        }
        // Reset Ball
        room.powerBall = false;
        room.ballX = room.canvasWidth / 2;
        room.ballY = room.canvasHeight / 2;
        room.speedY = room.defaultSpeedY;
        room.speedX = 0;
      }
    }

    if (room.ballY < room.paddleDiff) {
      // Bounce off computer paddle (top)
      if (room.ballX >= room.paddleX[1] && room.ballX <= room.paddleX[1] + room.paddleWidth) {
        // Set ball crood right on paddle
        room.ballY = room.paddleDiff;
        if (room.powerUp[1]) {
          // make ball power-up
          room.powerBall = true;
        } else {
          // turn off power-up ball speed
          room.powerBall = false;
          // Add Speed on Hit
          room.speedY += 1;
          // Max Speed
          if (room.speedY > room.maxSpeedY) {
            room.speedY = room.maxSpeedY;
          }
        }

          room.ballDirection = -room.ballDirection;
          room.speedX = room.speedX > 0 ?
            Math.random() * room.maxSpeedX :
            Math.random() * -room.maxSpeedX;
      } else {
        // Add to Player Score
        room.playerScore[0]++;
        // console.log(room.playerScore);
        // Game Over
        if (room.playerScore[0] >= 3) {
          clearInterval(room.interval);
          room.winner = room.player[0];
          room.loser = room.player[1];
          room.gameOver = true;
          // console.log("-----Game Over-----");
          // console.log("Winner:", room.winner.nickname);
          // console.log("Loser:", room.loser.nickname);
          // console.log("-------Score-------");
          // console.log(`${room.playerScore[0]} - ${room.player[0].nickname}`);
          // console.log(`${room.playerScore[1]} - ${room.player[1].nickname}`);
          return;
        }
        // Reset Ball
        room.powerBall = false;
        room.ballX = room.canvasWidth / 2;
        room.ballY = room.canvasHeight / 2;
        room.speedY = room.defaultSpeedY;
        room.speedX = 0;
      }
    }
  }

  getSocketByNickname(io: Namespace, nickname: string): GameSocket {
    let found: GameSocket;

    io.sockets.forEach((socket: GameSocket) => {
      if (socket.nickname === nickname) {
        found = socket;
      }
    });

    return found;
  }

  getSocketById(io: Namespace, id: number): GameSocket {
    let found: GameSocket;

    io.sockets.forEach((socket: GameSocket) => {
      if (socket.userId === id) {
        found = socket;
      }
    });

    return found;
  }

  objectsAreSame(x: Object, y: Object): boolean {
    var objectsAreSame: boolean = true;
    for(var propertyName in x) {
      // console.log(`x ${propertyName}: ${x[propertyName]}`);
      // console.log(`y ${propertyName}: ${y[propertyName]}`);
      if(x[propertyName] !== y[propertyName]) {
        // console.log(`${x[propertyName]}, ${y[propertyName]} - Not same`)
        objectsAreSame = false;
        break;
      }
    }
    // console.log("Same object");
    return objectsAreSame;
 }

 /**
  * 
  * const condition = (guests) => guests > 4;

// Use Array.from() and Map.prototype.keys() to filter and obtain matching room names
const roomsWithMoreThan4Guests = Array.from(roomMap.keys()).filter((room) => condition(roomMap.get(room))); 
this.rooms.forEach((_, key) => {
			if (key.includes(query)){
				if (this.findRoom(key).isPrivate == false)
					res.push(key);
			}
		})  
*/

 updateInGameStatus(io: Namespace, player1 : GameSocket, player2 : GameSocket, inGame : boolean) {
  const playerOneId = player1.userId;
  const playerTwoId = player2.userId;
  //all room list where playerOne or Two is joining
  const rooms = [];
  this.storeRoom.rooms.forEach((room, roomname) => {
    if (room.isJoinning(playerOneId) || room.isJoinning(playerTwoId))
      rooms.push(roomname);
  });
  //
  if (inGame) {
    player1.inGame = true;
    player2.inGame = true;
    io.emit('inGame', playerOneId);
    io.emit('inGame', playerTwoId);
    this.storeUser.findUserById(playerOneId).isGaming = true;
    this.storeUser.findUserById(playerTwoId).isGaming = true;
  }
  else {
    player1.inGame = false;
    player2.inGame = false;
    io.emit('NotInGame', playerOneId);
    io.emit('NotInGame', playerTwoId);
    this.storeUser.findUserById(playerOneId).isGaming = false;
    this.storeUser.findUserById(playerTwoId).isGaming = false;
  }
  //emit event for client to update screen
  rooms.forEach((roomname) => {
  const room : Room = this.storeRoom.findRoom(roomname);
  if (!room || room.userlist.size === 0)
    return ([]);
  const userInfo = [];
  room.userlist.forEach((user) => {
  const target : User = this.storeUser.findUserById(user);
  userInfo.push({
    id : user,
    nickname : target.nickname,
    isGaming : target.isGaming,
    isConnected : target.connected,
    })
  })
  io.in(roomname).emit("sendRoomMembers", userInfo);
  })
  // const  dmRooms = [];
  io.adapter.rooms.forEach(async (_, room : string) => {
    if (this.storeRoom.isDMRoom(room)) {
      if (this.storeRoom.isUserInDMRoom(playerOneId, room)
         || this.storeRoom.isUserInDMRoom(playerTwoId, room)){
          // console.log(room);
          const userInfo = [];
          const usersInDMRoom = this.storeRoom.parseIdsOfDMRoom(room);
          usersInDMRoom.forEach((userId) => {
            const user = this.storeUser.findUserById(userId);
            if (user){
              userInfo.push({
                id: user.id,
                nickname: user.nickname,
                isGaming: user.isGaming,
                isConnected: user.connected,
             })
            }
          })
			    io.in(room).emit("sendRoomMembers", userInfo);
      }
        //  dmRooms.push(room);
    }
    // dmRooms.forEach(async (room) => {
    //   const sockets = await io.in(room).fetchSockets();
    //   const userInfo = [];
    //   sockets.forEach((socket : GameSocket) => {
    //     const user = this.storeUser.findUserById(socket.userId);
    //     userInfo.push({
    //       id: user.id,
		// 	    nickname: user.nickname,
		// 	    isGaming: user.isGaming
    //     })
    //   })
		// 	io.in(room).emit("sendRoomMembers", userInfo);
    // })
  })
}


}
