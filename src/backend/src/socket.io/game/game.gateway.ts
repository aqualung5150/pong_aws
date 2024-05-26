import { Logger, ValidationPipe, UsePipes, UseFilters } from '@nestjs/common';
import {
	ConnectedSocket,
	OnGatewayConnection,
	OnGatewayDisconnect,
	OnGatewayInit,
	SubscribeMessage,
	WebSocketGateway,
	WebSocketServer,
} from '@nestjs/websockets';
import { Namespace } from 'socket.io';
import { GameSocket } from './types';
import { GameRoom } from './GameRoom';
import { GameService } from './game.service';
import { MatchService } from 'src/match/match.service';
import { WsExceptionFilter } from '../ws-exception.filter';
import { Invitation } from './dto/invitation.dto';
import { OneOnOnePayload } from './dto/one-on-on.dto';
import { KeydownPayload } from './dto/keydown.dto';

@UsePipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  transformOptions: { enableImplicitConversion: true },
}))
@UseFilters(WsExceptionFilter)
@WebSocketGateway({
	namespace: 'game',
	pingTimeout: 2000,
	pingInterval: 5000,
})
export class GameGateway
	implements OnGatewayConnection, OnGatewayDisconnect, OnGatewayInit
{
	private readonly logger = new Logger(GameGateway.name);
	private randomMatchQueue = {
		easy: [],
		normal: [],
		hard: []
	}
	private gameRooms = {};

	constructor(
		private gameService: GameService,
		private matchService: MatchService
	){}

	@WebSocketServer()
	io : Namespace;

	afterInit(){
		this.logger.log('GAME 웹소켓 서버 초기화 ✅');

		// Monitoring finished Game - clear game room instance
		setInterval(() => {
			for (let e in this.gameRooms) {
				// console.log("GameRoom:", e);
				if (this.gameRooms[e].gameOver) {
				const room: GameRoom = this.gameRooms[e];
				if (room.gameStart) {
          this.logger.log(`Game Over - Winner: ${room.winner.nickname} Loser: ${room.loser.nickname}`);
					// Save Game Result in DB
					this.matchService.createMatchHistory({
						winnerId: room.winner.userId,
						loserId: room.loser.userId
					})
					this.io.to(e).emit('gameOver', {
					roomName: e,
					winner: room.winner.nickname,
					loser: room.loser.nickname
					});
				}

				// Set player status
        // CHECK : if either of player can be non-exist
        if (room.player[0] && room.player[1])
            this.gameService.updateInGameStatus(
            this.io.server.of('chat'),
            room.player[0], room.player[1],
            false
        );

				// Delete GameRoom Instance
				delete this.gameRooms[e];
				}
			}
		}, 1000)
	}

	handleConnection(@ConnectedSocket() client: GameSocket) {
    client.emit("hello");

		client.inGame = false;
		client.invitationList = [];

    // //TEST
    // client.userId = 1234;
    // client.nickname = "def";

    // client.color = "#" + Math.floor(Math.random()*16777215).toString(16);
    // client.color = "hsl(" + (Math.random() * 360) + ",100%, 50%)"
    function getRandom(min: number, max: number)
    {
      return Math.floor(Math.random() * (max - min + 1) + min);
    }
    const randomNumber = getRandom(0, 36);
    client.color = "hsl(" + (randomNumber * 10) + ",100%, 50%)"

		const sockets = this.io.sockets;
		this.logger.log(`Game Client Connected : ${client.nickname}`);
		this.logger.log(`Number of connected Game sockets: ${sockets.size}`)
  }

	handleDisconnect(@ConnectedSocket() client: GameSocket) {
		// leave game
		if (client.inGame) {
      // Notify every socket that client is not in game
      // this.io.server.of('chat').emit("NotInGame", client.nickname);
			for (let e in this.gameRooms) {
				const room: GameRoom = this.gameRooms[e];
				// If client is in game
				if (room.player[0] || room.player[1]) {
					// Set Room Game Over - monitoring interval will emit/clean the room
					room.gameOver = true;
					// if started game
					if (room.gameStart) {
						// Stop Inteval
						clearInterval(room.interval);
						// Set winner
						room.winner = client === room.player[0] ? room.player[1] : room.player[0];
						room.loser = client;

            this.logger.log(`Game Over - Winner: ${room.winner.nickname} Loser: ${room.loser.nickname}`);
						// console.log("-----Game Over-----");
						// console.log("Winner:", room.winner.nickname);
						// console.log("Loser:", room.loser.nickname);
						// console.log("-------Score-------");
						// console.log(`${room.playerScore[0]} - ${room.player[0].id}`);
						// console.log(`${room.playerScore[1]} - ${room.player[1].id}`);
            
            this.gameService.updateInGameStatus(
              this.io.server.of('chat'),
              room.player[0],
              room.player[1],
              true
            )
					} else {
						this.io.to(room.name).emit('matchDecline', room.name);
					}
				}
			}
		}

    // clear invitation
    const sockets = this.io.sockets;

    sockets.forEach((socket: GameSocket) => {
      let disconnectedInvitation = false;
      // disconnected socket's list
      client.invitationList.forEach((invit: Invitation) => {
        if (socket.invitationList.includes(invit)) {
          disconnectedInvitation = true;
          socket.invitationList = socket.invitationList.filter(item => item !== invit);
        }
      })

      // 
      if (disconnectedInvitation) {
        socket.emit('updateInvitationList', socket.invitationList);
      }
    });

		this.logger.log(`Game Client Disconnected : ${client.nickname}`);
		this.logger.log(`Number of connected Game sockets: ${sockets.size}`)
	}

  /*-------------Random Match-----------------------*/

  @SubscribeMessage('randomMatchApply')
  handleRandomMatchApply(client: GameSocket, mode: string) {
    // client is in game
    // console.log(mode);
    if (client.inGame) {
      return;
    }

	// if no matched mode, set default mode to normal
	if (!mode || (mode !== "easy" && mode !== "normal" && mode !== "hard")) {
		mode = "normal";
		this.logger.log(`mode set to default: ${mode}`);
	}

    // set random match queue
	let matchQueue: GameSocket[] = this.randomMatchQueue[mode];

    // remove duplication
    if (matchQueue.includes(client)) {
      return;
    }

	// delete client from other random match queue
	for (let e in this.randomMatchQueue) {
		if (e !== mode) {
			this.randomMatchQueue[e] = this.randomMatchQueue[e].filter(item => item !== client);
		}
	}

    // push client in queue
    matchQueue.push(client);

	// console.log(this.randomMatchQueue["easy"].length);
	// console.log(this.randomMatchQueue["normal"].length);
	// console.log(this.randomMatchQueue["hard"].length);

    // More than 2 players in queue
    if (matchQueue.length >= 2) {
      let playerOne = matchQueue[0];
      let playerTwo = matchQueue[1];
      // if player aleady is in game
      // delete player from queue
      if (playerOne.inGame) {
        matchQueue =
          matchQueue.filter(item => item !== playerOne);
        return;
      }
      if (playerTwo.inGame) {
        matchQueue =
          matchQueue.filter(item => item !== playerTwo);
        return;
      }
      // Create New Game Room
      const roomName = `room_${playerOne.nickname}_${playerTwo.nickname}`;
      this.gameRooms[roomName] = new GameRoom({
        name: roomName,
        player: [playerOne, playerTwo],
        mode: mode
      });

      this.gameService.updateInGameStatus(
        this.io.server.of('chat'),
        playerOne,
        playerTwo,
        true
      )

      this.logger.log(`Create Game Room - ${roomName}`);

      // Add Players into Game Room
      playerOne.join(roomName);
      playerTwo.join(roomName);
      // Delete Players from Random Match Queue
      matchQueue.splice(0, 2);
      // Ask Match Accept
      this.io.to(roomName).emit('matchStartCheck', {
        roomName: roomName,
        player: [playerOne.nickname, playerTwo.nickname],
        mode: mode
      });
    }
  }

  @SubscribeMessage('randomMatchCancel')
  handleRandomMatchCancel(client: GameSocket) {
	for (const e in this.randomMatchQueue) {
		this.randomMatchQueue[e] = this.randomMatchQueue[e].filter(item => item !== client);
	}

	// console.log(this.randomMatchQueue["easy"].length);
	// console.log(this.randomMatchQueue["normal"].length);
	// console.log(this.randomMatchQueue["hard"].length);
  }

  /*-------------Match Accept-----------------------*/

  @SubscribeMessage('matchAccept')
  handleAccept(client: GameSocket, roomName: string) {
    let room: GameRoom = this.gameRooms[roomName];

    this.logger.debug(roomName);

    // check if user in the room
    this.gameService.validatePlayerInRoom(client, room);
  // check if room is already in game
    if (room.gameStart) {
      return;
    }

    if (client.id === room.player[0].id) {
      room.playerAccept[0] = true;
    }
    else if (client.id === room.player[1].id) {
      room.playerAccept[1] = true;
    }

    // Start Game
    if (room.playerAccept[0] && room.playerAccept[1]) {
      this.gameService.startGame(this.io, room);
    };
    
  }

  @SubscribeMessage('matchDecline')
  handleDecline(client: GameSocket, roomName:string) {
    // check if user in the room
    this.gameService.validatePlayerInRoom(client, this.gameRooms[roomName]);
    // check if room is already in game
    const room = this.gameRooms[roomName];

    if (room.gameStart) {
      return;
    }

    this.gameService.updateInGameStatus(
      this.io.server.of('chat'),
      room.player[0], room.player[1],
      false
    )

    this.io.to(roomName).emit('matchDecline', roomName);
    // delete game room
    delete this.gameRooms[roomName];
  }

  /*---------------------One on One-----------------------------------*/

  @SubscribeMessage('oneOnOneApply')
  handleOneOnOneApply(client: GameSocket, payload: OneOnOnePayload) {
    if (payload.to === client.nickname) {
      return `ERR you invite yourself: ${payload.to}`;
    }
    // Get By Nickname
    const toClient: GameSocket = this.gameService.getSocketByNickname(this.io, payload.to);

    if (!toClient) {
      return `ERR no such user: ${payload.to}`;
    }

    // New Invitation
    const invitation: Invitation = {
      from: client.nickname,
      fromId: client.userId,
      to: payload.to,
      toId: toClient.userId,
      mode: payload.mode,
    }

    // 중복확인
    for (let e in client.invitationList) {
      if (this.gameService.objectsAreSame(client.invitationList[e], invitation)) {
        return `ERR aleady invite ${payload.to}`;
      }
    }

    // update list on each client
    client.invitationList.push(invitation);
    toClient.invitationList.push(invitation);

    // send invitation list
    client.emit('updateInvitationList', client.invitationList);
    toClient.emit('updateInvitationList', toClient.invitationList);

    // console.log(`${client.nickname} - list size: ${client.invitationList.length}`);
    // console.log(`${toClient.nickname} - list size: ${toClient.invitationList.length}`);
  }

  @SubscribeMessage('oneOnOneAccept')
  handleOneOnOneAccept(client: GameSocket, payload: Invitation) {
    if (client.inGame) {
      return `ERR ${client.nickname} is in game`;
    }
    // Get By Nickname
    const fromClient: GameSocket = this.gameService.getSocketByNickname(this.io, payload.from);

    if (fromClient?.inGame) {
      return `ERR ${payload.from} is in game`;
    }

    for (let e in client.invitationList) {
      if (client.invitationList[e].from === payload.from) {
      // delete invitation from client
      client.invitationList = client.invitationList.filter((item: Invitation) => 
      !this.gameService.objectsAreSame(item, payload));
      // send invitation list to client
      client.emit('updateInvitationList', client.invitationList);

        if (!fromClient) {
          return `ERR no such user: ${payload.from}`;
        }

        // Create New Game Room
        const roomName = `room_${fromClient.nickname}_${client.nickname}`;
        this.gameRooms[roomName] = new GameRoom({
          name: roomName,
          player: [fromClient, client],
          mode: payload.mode
        });

        this.gameService.updateInGameStatus(
          this.io.server.of('chat'),
          client, fromClient,
          true
        )

        // Add Players into Game Room
        fromClient.join(roomName);
        client.join(roomName);

        this.logger.log(`Create Game Room - ${roomName}`);

        // Delete Invitations from fromClient
        fromClient.invitationList = fromClient.invitationList.filter((item: Invitation) => 
          !this.gameService.objectsAreSame(item, payload));
		    // send invitation list to fromClient
		    fromClient.emit('updateInvitationList', fromClient.invitationList);

        // Ask Match Accept
        this.io.to(roomName).emit('matchStartCheck', {
          roomName: roomName,
          player: [fromClient.nickname, client.nickname],
          mode: payload.mode
        });

        // console.log(`${fromClient.id} - list size: ${fromClient.invitationList.length}`);
        // console.log(`${client.id} - list size: ${client.invitationList.length}`);
        
        return;
      }
    }
    return `ERR no invitation from ${payload.from}`;
  }

  @SubscribeMessage('oneOnOneDecline')
  handleOneOnOneDecline(client: GameSocket, payload: Invitation) {
    // delete invitation from client
    client.invitationList = client.invitationList.filter((item: Invitation) => 
      !this.gameService.objectsAreSame(item, payload));
    // emit updated list
    client.emit('updateInvitationList', client.invitationList);

	  // Get another player socket by nickname
    let anotherClient: GameSocket;

    if(client.nickname === payload.from) {
      anotherClient = this.gameService.getSocketByNickname(this.io, payload.to);
    } else {
      anotherClient = this.gameService.getSocketByNickname(this.io, payload.from);
    }
    if (anotherClient) {
      // delete invitation from client
      anotherClient.invitationList = anotherClient.invitationList.filter((item: Invitation) => 
      !this.gameService.objectsAreSame(item, payload));
      // emit updated list
      anotherClient.emit('updateInvitationList', anotherClient.invitationList);
    }
  }

  /*---------------------In Game--------------------------------------*/

  // In Game
  @SubscribeMessage('keydown')
  handleKeydown(client: GameSocket, payload: KeydownPayload) {
    // client is not in game
    if (!client.inGame) {
      return;
    }

    // check if user in the room
    this.gameService.validatePlayerInRoom(client, this.gameRooms[payload.roomName]);

    let room = this.gameRooms[payload.roomName];

    switch (payload.key) {
      case 'ArrowLeft':
        if (client === room.player[0]) {
          room.paddleX[0] -= 7;
          if (room.paddleX[0] <= 0) {
            room.paddleX[0] = 0;
          }
        }
        else {
          room.paddleX[1] -= 7;
          if (room.paddleX[1] <= 0) {
            room.paddleX[1] = 0;
          }
        }
        break;
      case 'ArrowRight':
        if (client === room.player[0]) {
          room.paddleX[0] += 7;
          if (room.paddleX[0] >= room.canvasWidth - room.paddleWidth) {
            room.paddleX[0] = room.canvasWidth - room.paddleWidth;
          }
        }
        else {
          room.paddleX[1] += 7;
          if (room.paddleX[1] >= room.canvasWidth - room.paddleWidth) {
            room.paddleX[1] = room.canvasWidth - room.paddleWidth;
          }
        }
        break;
      case ' ':
        if (client === room.player[0] && room.powerPoint[0] > 0) {
          room.powerUp[0] = true;
          --room.powerPoint[0];
          setTimeout(() => {
            room.powerUp[0] = false;
          }, 10000);
        } else if (client === room.player[1] && room.powerPoint[1] > 0) {
          room.powerUp[1] = true;
          --room.powerPoint[1];
          setTimeout(() => {
            room.powerUp[1] = false;
          }, 10000);
        }

    }
  }
  /*-----------------------Nickname Changed------------------------------*/
  @SubscribeMessage('changeNick')
  handleNicknameChanged(client: GameSocket, nickname: string) {
    if (nickname === client.nickname) {
      return;
    }
	const sockets = this.io.sockets;
	const oldNickname = client.nickname;

	/*
	얕은 복사가 이뤄졌기 때문에 Invitation 객체가 수정되면 이 객체를 가지고 있는 다른 invitationList도 값이 변경됨.
	=> 주소값을 공유하고 있는 형태
	*/
	client.invitationList.forEach((invit: Invitation) => {
		if (invit.from === oldNickname) {
			invit.from = nickname;
		} else if (invit.to === oldNickname) {
			invit.to = nickname;
		}
	});

	// emit
	sockets.forEach((socket: GameSocket) => {
		socket.invitationList.every((invit: Invitation) => {
			if (invit.from === nickname || invit.to === nickname) {
				socket.emit('updateInvitationList', socket.invitationList);
				return false;
			}
      return true;
		});
	});
  // sockets.forEach((socket: GameSocket) => {
	// 	socket.invitationList.forEach((invit: Invitation) => {
	// 		if (invit.from === nickname || invit.to === nickname) {
	// 			socket.emit('updateInvitationList', socket.invitationList);
	// 			return false;
	// 		}
	// 	});
	// });

	// Set client's new nickname
	this.logger.log(`${client.nickname} is now ${nickname}`);
	client.nickname = nickname;
  }

  updateUserNick(id : number, newNick : string) {
    const client = this.gameService.getSocketById(this.io, id);
    // const client = this.gameService.getSocketByNickname(this.io, nickname);

    if (newNick === client.nickname) {
      return;
    }
    const sockets = this.io.sockets;
    const oldNickname = client.nickname;

    client.invitationList.forEach((invit: Invitation) => {
      if (invit.from === oldNickname) {
        invit.from = newNick;
      } else if (invit.to === oldNickname) {
        invit.to = newNick;
      }
    });

    // emit
    sockets.forEach((socket: GameSocket) => {
      client.invitationList.every((invit: Invitation) => {
        if (socket.invitationList.includes(invit)) {
          socket.emit('updateInvitationList', socket.invitationList);
          return false;
        }
        return true;
      })
    });

    // sockets.forEach((socket: GameSocket) => {
    //   socket.invitationList.every((invit: Invitation) => {
    //     if (invit.from === newNick || invit.to === newNick) {
    //       socket.emit('updateInvitationList', socket.invitationList);
    //       return false;
    //     }
    //     return true;
    //   });
    // });

    this.logger.log(`${client.nickname} is now ${newNick}`);
    client.nickname = newNick;
	}
}