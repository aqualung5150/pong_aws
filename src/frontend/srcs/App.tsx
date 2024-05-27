import { useEffect, useState } from "react";
import { useRouter } from "next/router";

import * as io from "socket.io-client";
import { Socket } from "socket.io-client";
import ModalBasic from "./components/modalpage/modal";
import ModalOverlay from "./components/modalpage/ModalOverlay";
import NavBar from "./components/navpage/NavBar";
import GameList from "./components/gamelistpage/GameList";
import ChatMain from "./components/chatpage/ChatMain";
import SearchList from "./components/searchlistpage/SearchList";
import DirectMessageList from "./components/dmlist/DirectMessageList";
import ChatRoomUser from "./components/chatroompage/ChatRoom";

import ModalAlert from "./components/modalpage/ModalAlert";
// import Pong, { AutoSave, GameOverData, StartGameData } from "@/srcs/Pong";
import Pong, {
  AutoSave,
  GameOverData,
  StartGameData,
} from "./components/pong/Pong";
// import { SocketContext, socket } from "../context/socket";
// import searchIcon from "./assets/search.png";
import Image from "next/image";
import TempRandomMatch from "./components/pong/TempRandomMatch";
import { SocketContext } from "@/context/socket";
import { GameContext, GameData } from "@/context/game";
import axiosApi from "./AxiosInterceptor";
export type UserOnChat = {
  id: string;
  isCreator: boolean;
  isOp: boolean;
};

export type TempSearch = {
  roomname: string;
  lastMessage: string;
  lastMessageFrom: string;
  messageNew: boolean;
  users: UserOnChat[];
};

export default function App() {
  const [tmpLoginID, setTmpLoginID] = useState<string>("");
  const [tmpLoginnickname, setTmpLoginnickname] = useState<string>("");
  const [tmpIsLoggedIn, setTmpIsLoggedIn] = useState<boolean>(false);

  const [results, setTempSearchList] = useState<TempSearch[]>([]);

  const [roomUserList, setRoomUserList] = useState<any>(null);

  const [roomnameModal, setroomnameModal] = useState<string>("");
  const [currentRoomName, setCurrentRoomName] = useState<string>("");
  const [leftHeader, setLeftHeader] = useState<string>("");
  const [isOpenModal, setIsOpenModal] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const [messages, setMessages] = useState<any>(new Array());
  const [roomInfo, setRoomInfo] = useState<any>(null);
  const [blocklist, setBlocklist] = useState<any>(new Array());

  const [alertModal, setAlertModal] = useState<boolean>(false);
  const [alertModalTitle, setAlertModalTitle] = useState<string>("");
  const [alertModalBody, setAlertModalBody] = useState<string>("");
  const [isDM, setIsDM] = useState<boolean>(false);
  const [DMTargetId, setDMTargetId] = useState<number>(-1);
  // seunchoi - for socket connection
  const [gameLoad, setGameLoad] = useState<boolean>(false);
  // Get Empty Socket Instance
  const [socket, setSocket] = useState<Socket>(
    io.connect("", {
      query: { nickname: "" },
      autoConnect: false,
      transports: ["websocket"]
    })
  );
  const [gameSocket, setGameSocket] = useState<Socket>(
    io.connect("", {
      query: { nickname: "" },
      autoConnect: false,
      transports: ["websocket"]
    })
  );

  const [changedID, setChangedID] = useState<number>(-2);
  const [changedNickName, setChangedNickName] = useState<string>("");

  const router = useRouter();

  const [lastMessageList, setLastMessageList] = useState<any>(new Map());
  const [directMessageMap, setDirectMessageMap] = useState<any>(new Map());
  const [directMessageList, setDirectMessageList] = useState<any>(new Array());
  useEffect(() => {
    function reloadNick(userId: number, newNick: string) {
      setChangedID(() => userId);
      setChangedNickName(() => newNick);

      const nicknameItem = localStorage.getItem("nickname");
      const loginIdItem = localStorage.getItem("id");

      if (loginIdItem === String(userId)) {
        setTmpLoginnickname(newNick);
      }
    }

    function updateUserNick(userId: number, newNick: string) {
      let max = directMessageMap;

      if (max.get(userId)) {
        const tmpData = max.get(userId);
        tmpData.data.from = newNick;
        max.set(userId, {
          data: tmpData.data,
        });
      }

      if (userId === Number(tmpLoginID)) {
        setTmpLoginnickname(() => newNick);
      }
      setDirectMessageMap(() => max);
      setDirectMessageList(() => [...max]);
    }
    if (socket) {
      socket.on("updateUserNick", updateUserNick);
    }
    return () => {
      if (socket) {
        socket.off("updateUserNick", updateUserNick);
      }
    };
  }, [socket]);

  useEffect(() => {
    async function checkLogout(userId: number, isConnected: boolean) {
      if (isConnected == false && userId == Number(tmpLoginID)) {
        alert("로그인 정보가 만료되었습니다");
        localStorage.setItem("isLoggedIn", "false"); //다른 브라우저에서 내 계정으로 로그아웃 했을 시
        localStorage.removeItem("id");
        localStorage.removeItem("nickname");
        localStorage.removeItem("is2fa");
        localStorage.removeItem("access_token");
        localStorage.removeItem("access_token_exp");
        localStorage.removeItem("avatar");
        sessionStorage.removeItem("gamesocket");
        setTimeout(() => router.push("/", undefined, { shallow : true }), 10);
      }
    }
    if (socket) {
      socket.on("updateUserStatus", checkLogout);
    }
    return () => {
      if (socket) {
        socket.off("updateUserStatus", checkLogout);
      }
    };
  }, [socket, tmpLoginID]);

  useEffect(() => {
    const getSocket = (namespace: string, jwt: string, nickname: string) => {
      return io.connect(`http://${process.env.NEXT_PUBLIC_BASE_URL}/${namespace}`, {
        query: { nickname: nickname },
        auth: { token: jwt },
        transports: ["websocket"]
      });
    };

    const nicknameItem = localStorage.getItem("nickname");
    const loginIdItem = localStorage.getItem("id");
    if (nicknameItem && loginIdItem) {
      setTmpLoginnickname(nicknameItem);
      setTmpLoginID(loginIdItem);
      setTmpIsLoggedIn(true);
    }
    const jwtItem = localStorage.getItem("access_token");

    let chatConnection: Socket;
    let gameConnection: Socket;

    // Run whenever jwt state updated
    if (nicknameItem && jwtItem) {
      chatConnection = getSocket("chat", jwtItem, nicknameItem);
      gameConnection = getSocket("game", jwtItem, nicknameItem);
      setSocket(chatConnection);
      setGameSocket(gameConnection);
    }

    return () => {
      if (chatConnection.connected) {
        chatConnection.disconnect();
      }
      if (gameConnection.connected) {
        gameConnection.disconnect();
      }
    };
  }, []);

  //TEST
  // useEffect(() => {
  //   const interval: any = setInterval(() => {
  //     const e = Date.now();
  //     setQuery(e.toString());
  //   }, 100);
  //   setTimeout(() => {
  //     clearInterval(interval);
  //   }, 100000)
  // }, [])

  useEffect(() => {
    let blockListItem = localStorage.getItem("blocklist");

    if (typeof blockListItem === "string") {
      blockListItem = blockListItem.substr(1, blockListItem.length - 2);
      const arr = blockListItem.split(",");
      const numberArray: any = [];
      const length = arr.length;
      for (var i = 0; i < length; i++) numberArray.push(parseInt(arr[i]));

      setBlocklist(() => numberArray);
    }
  }, []);

  useEffect(() => {
    function sendBlocklist(result: any) {
      localStorage.setItem("blocklist", JSON.stringify(result));
      setBlocklist(() => [...result]);
    }

    function sendRoomMembers(result: any) {
      setRoomUserList(() => result);
      setLeftHeader(() => "joined");
      // setQuery("");
    }

    function sendMessage(roomname: string, data: any) {
      let max = lastMessageList;
      results.map((result: any) => {
        let chkNew;

        if (currentRoomName === result.roomname) {
          result.messageNew = false;
          result.lastMessage = data.body;
          result.fromId = data.fromId;
          result.at = data.at;
          max.set(result.roomname, {
            fromId: result?.fromId,
            lastMessage: result.lastMessage,
            messageNew: false,
            at: result?.at,
          });
          return result;
        }
        return result;
      });

      setLastMessageList(() => max);
      setTempSearchList(() => results);

      if (roomname === currentRoomName && !isDM) {
        setMessages(() => [...messages, data]);
      }
    }

    function sendDM(to: string, data: any) {
      let max = directMessageMap;

      if (
        data?.from !== tmpLoginnickname &&
        !blocklist.includes(data?.fromId) &&
        data?.fromId !== DMTargetId
      )
        max.set(data?.fromId, {
          data,
          messageNew: false,
        });
      const chk = data?.fromId === DMTargetId && isDM;

      if (data?.fromId === DMTargetId && isDM) {
        socket.emit("userCheckedDM", { targetId: data?.fromId });
      }

      setDirectMessageList(() => [...directMessageMap]);
      setDirectMessageMap(() => max);

      if (
        isDM &&
        ((data?.from === currentRoomName && to === tmpLoginnickname) ||
          (to === currentRoomName && data?.from === tmpLoginnickname))
      ) {
        setMessages(() => [...messages, data]);
      }
    }
    function youAreKickedOut(result: any) {}
    function youAreBanned(result: any) {}
    function wrongPassword(result: any) {}
    function sendAlert(alertTitle: string, alertBody: string) {
      setAlertModalTitle(() => alertTitle);
      setAlertModalBody(() => alertBody);
      setAlertModal(() => true);
    }

    function userCheckedDM(fromId: any) {
      const tmpList: any = [];
      directMessageList.map((e: any) => {
        if (e?.[1].data.fromId !== fromId) tmpList.push(e);
      });
      let tmpMap = directMessageMap;
      tmpMap.delete(fromId);

      setDirectMessageList(() => tmpList);
      setDirectMessageMap(() => tmpMap);
    }
    if (socket) {
      socket.on("userCheckedDM", userCheckedDM);
      socket.on("sendAlert", sendAlert);
      socket.on("sendBlocklist", sendBlocklist);
      // socket.on("updateBlocklist", updateBlocklist);
      socket.on("youAreKickedOut", youAreKickedOut);
      socket.on("youAreBanned", youAreBanned);
      socket.on("wrongPassword", wrongPassword);
      socket.on("sendDM", sendDM);
      socket.on("sendMessage", sendMessage);
      socket.on("sendRoomMembers", sendRoomMembers);
    }

    return () => {
      if (socket) {
        socket.off("userCheckedDM", userCheckedDM);
        socket.off("sendAlert", sendAlert);
        socket.off("sendBlocklist", sendBlocklist);
        // socket.off("updateBlocklist", updateBlocklist);
        socket.off("youAreKickedOut", youAreKickedOut);
        socket.off("youAreBanned", youAreBanned);
        socket.off("wrongPassword", wrongPassword);
        socket.off("sendMessage", sendMessage);
        socket.off("sendRoomMembers", sendRoomMembers);
        socket.off("sendDM", sendDM);
      }
    };
  }, [
    currentRoomName,
    results,
    messages,
    socket,
    blocklist,
    isDM,
    directMessageMap,
    directMessageList,
  ]);

  // Game
  const handleGameOnOff = () => {
    setGameLoad(!gameLoad);
  };

  const [isGameConnected, setIsGameConnected] = useState<boolean>(false);
  const [roomName, setRoomName] = useState<string>("");
  const [matchStartCheck, setMatchStartCheck] = useState<boolean>(false);
  const [gameData, setGameData] = useState<GameData>({
    inGame: false,
    gameOver: false,
    player: [],
    playerColor: [],
    canvasWidth: 900,
    canvasHeight: 1600,
    paddleWidth: 0,
    paddleHeight: 0,
    ballRadius: 0,
    winner: "",
    loser: "",
  });

  useEffect(() => {
    if (isGameConnected == true) {
      sessionStorage.setItem("gamesocket", "true");
    } else {
      sessionStorage.setItem("gamesocket", "false");
    }
  }, [isGameConnected]);

  useEffect(() => {
    gameSocket.on("hello", () => {
      setIsGameConnected(true);
    });

    gameSocket.on("matchStartCheck", (payload: AutoSave) => {
      console.log(payload.roomName + "in matchStartCheck");
      setRoomName(payload.roomName);
      setMatchStartCheck(true);
    });

    gameSocket.on("matchDecline", (payload: string) => {
      setRoomName("");
      setMatchStartCheck(false);
    });

    gameSocket.on("startGame", (payload: StartGameData) => {
      setMatchStartCheck(false);
      setGameLoad(true);

      setGameData({
        inGame: true,
        gameOver: false,
        player: payload.player,
        playerColor: payload.playerColor,
        canvasWidth: payload.canvasWidth,
        canvasHeight: payload.canvasHeight,
        paddleWidth: payload.paddleWidth,
        paddleHeight: payload.paddleHeight,
        ballRadius: payload.ballRadius,
        winner: "",
        loser: "",
      });
    });

    gameSocket.on("gameOver", (payload: GameOverData) => {
      setGameData({
        inGame: false,
        gameOver: true,
        player: [],
        playerColor: [],
        canvasWidth: 0,
        canvasHeight: 0,
        paddleWidth: 0,
        paddleHeight: 0,
        ballRadius: 0,
        winner: payload.winner,
        loser: payload.loser,
      });
    });
  }, [gameSocket]); // gameData?
  // }, [gameSocket, isGameConnected, gameData]) // gameData?

  return (
    <SocketContext.Provider
      value={{
        chatSocket: socket,
        gameSocket: gameSocket,
      }}
    >
      {
        <>
          <ModalOverlay isOpenModal={alertModal} />
          <>
            {alertModal && (
              <ModalAlert
                alertTitle={alertModalTitle}
                alertBody={alertModalBody}
                setIsOpenModal={setAlertModal}
              />
            )}
          </>
          <ModalOverlay isOpenModal={isOpenModal} />
          <>
            {isOpenModal && (
              <ModalBasic
                roomname={roomnameModal}
                setIsOpenModal={setIsOpenModal}
                innerText={"비밀번호 입력하세요"}
              />
            )}
          </>
          {/* seunchoi - TEST */}

          <GameContext.Provider
            value={{
              isGameConnected: isGameConnected,
              matchStartCheck: matchStartCheck,
              roomName: roomName,
              gameData: gameData,
            }}
          >
            <NavBar
              setIsLoading={setIsLoading}
              setTmpLoginnickname={setTmpLoginnickname}
              setLeftHeader={setLeftHeader}
              setError={setError}
              isGameConnected={isGameConnected}
              matchStartCheck={matchStartCheck}
              handleGameOnOff={handleGameOnOff}
              gameLoad={gameLoad}
            />
          </GameContext.Provider>
          <Main>
            <Box>
              {
                <>
                  <SearchList
                    results={results}
                    setTempSearchList={setTempSearchList}
                    isOpenModal={isOpenModal}
                    setIsOpenModal={setIsOpenModal}
                    leftHeader={leftHeader}
                    setLeftHeader={setLeftHeader}
                    setroomnameModal={setroomnameModal}
                    blocklist={blocklist}
                    currentRoomName={currentRoomName}
                    setCurrentRoomName={setCurrentRoomName}
                    lastMessageList={lastMessageList}
                    setLastMessageList={setLastMessageList}
                    setError={setError}
                    setIsLoading={setIsLoading}
                  />
                  <DirectMessageList
                    myNickName={tmpLoginnickname}
                    directMessageList={directMessageList}
                    setDirectMessageList={setDirectMessageList}
                    directMessageMap={directMessageMap}
                    setDirectMessageMap={setDirectMessageMap}
                    isDM={isDM}
                    setIsDM={setIsDM}
                    currentRoomName={currentRoomName}
                  />
                </>
              }
            </Box>
            {gameLoad && (
              <GameContext.Provider
                value={{
                  isGameConnected: isGameConnected,
                  matchStartCheck: matchStartCheck,
                  roomName: roomName,
                  gameData: gameData,
                }}
              >
                <Pong />
              </GameContext.Provider>
            )}

            <ChatMain
              isDM={isDM}
              setIsDM={setIsDM}
              roomInfo={roomInfo}
              setRoomInfo={setRoomInfo}
              messages={messages}
              setMessages={setMessages}
              currentRoomName={currentRoomName}
              setCurrentRoomName={setCurrentRoomName}
              myNickName={tmpLoginnickname}
              blocklist={blocklist}
              gameLoad={gameLoad}
              setDMTargetId={setDMTargetId}
            />

            <Box>
              <>
                <ChatRoomUser
                  id={tmpLoginID}
                  isDM={isDM}
                  isGameConnected={isGameConnected}
                  blocklist={blocklist}
                  roomInfo={roomInfo}
                  setRoomInfo={setRoomInfo}
                  users={roomUserList}
                  roomname={currentRoomName}
                  myNickName={tmpLoginnickname}
                  changedID={changedID}
                  changedNickName={changedNickName}
                />
                <GameList
                  myNickName={tmpLoginnickname}
                  setMatchStartCheck={setMatchStartCheck}
                />
              </>
            </Box>
          </Main>
        </>
      }
    </SocketContext.Provider>
  );
}

function DMlist() {
  return (
    <div className="dmlist-header">
      <h4>DM-List</h4>
    </div>
  );
}

function Main({ children }: { children: any }) {
  return <main className="main">{children}</main>;
}

function Box({ children }: { children: any }) {
  return <div className="box">{children}</div>;
}
