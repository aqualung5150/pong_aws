import { SocketContext } from "@/context/socket";
import { useContext } from "react";
export default function GameListItemInfo({
  game,
  myNickName,
  setMatchStartCheck,
}: {
  game: any;
  myNickName: string;
  setMatchStartCheck: any;
}) {
  const gameSocket = useContext(SocketContext).gameSocket;

  function handleCancle(event: any) {
    gameSocket.emit("oneOnOneDecline", game);
  }
  function handleAccept(event: any) {
    gameSocket.emit("oneOnOneAccept", game);
    // setMatchStartCheck(() => true);
  }
  function handleDecline(event: any) {
    gameSocket.emit("oneOnOneDecline", game);
  }
  if (!game?.to || !game?.from || !game?.mode) {
    return;
  } else {
    return (
      <>
        {game?.to === myNickName ? (
          <li>
            <div className="gamelist-avatar left">
              <img
                src={`http://localhost:80/api/user/${game?.fromId}/photo`}
                width="35"
                height="35"
                alt="avataricon"
              />
            </div>
            <div className="gamelist-textInfo">{`${game?.from}님이 ${game?.mode}게임을 신청하셨습니다`}</div>
            <div className="gamelist-confirm">
              <span onClick={() => handleAccept(event)} className="gameAccept">
                수락
              </span>
              <span> / </span>
              <span
                onClick={() => handleDecline(event)}
                className="gameDecline"
              >
                거절
              </span>
            </div>
            <div className="gamelist-avatar right">
              <img
                src={`http://localhost:80/api/user/${game?.toId}/photo`}
                width="35"
                height="35"
                alt="avataricon"
              />
            </div>
          </li>
        ) : (
          <li>
            <div className="gamelist-avatar left">
              <img
                src={`http://localhost:80/api/user/${game?.fromId}/photo`}
                width="35"
                height="35"
                alt="avataricon"
              />
            </div>
            <div className="gamelist-textInfo">{`${game?.to}님에게 ${game?.mode}게임을 신청하셨습니다`}</div>
            <div className="gamelist-confirm">
              <span onClick={() => handleCancle(event)} className="gameCancel">
                취소
              </span>
            </div>
            <div className="gamelist-avatar right">
              <img
                src={`http://localhost:80/api/user/${game?.toId}/photo`}
                width="35"
                height="35"
                alt="avataricon"
              />
            </div>
          </li>
        )}
      </>
    );
  }
}
