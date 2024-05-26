import GameListItemInfo from "./GameListItemInfo";
import { useContext } from "react";
// import { SocketContext } from "@/context/socket";
export default function GameListBody({
  myNickName,
  tmpList,
  setMatchStartCheck,
}: {
  myNickName: string;
  tmpList: any;
  setMatchStartCheck: any;
}) {
  // const socket = useContext(SocketContext).chatSocket;
  if (tmpList?.length === 0 || !tmpList) {
    return;
  } else {
    return (
      <div className="gamelist-body">
        <ul className="gamelist-lists">
          {tmpList.map((game: any, i: number) => (
            <GameListItemInfo
              game={game}
              key={i}
              myNickName={myNickName}
              setMatchStartCheck={setMatchStartCheck}
            />
          ))}
        </ul>
      </div>
    );
  }
}
