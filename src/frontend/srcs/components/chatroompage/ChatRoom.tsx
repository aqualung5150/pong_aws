import ChatRoomUserInfo from "./ChatRoomUserInfo";
import { useEffect, useState, useContext } from "react";
// import { SocketContext } from "@/context/socket";
import axiosApi from "../../AxiosInterceptor";
const pageHeight = 8;
export default function ChatRoomUser({
  id,
  isDM,
  users,
  blocklist,
  roomInfo,
  setRoomInfo,
  roomname,
  myNickName,
  changedID,
  changedNickName,
  isGameConnected,
}: {
  id: any;
  isDM: boolean;
  users: any;
  blocklist: any;
  roomInfo: any;
  setRoomInfo: any;
  roomname: string;
  myNickName: string;
  changedID: number;
  changedNickName: string;
  isGameConnected: boolean;
}) {
  const [page, setPage] = useState<number>(1);
  const [leftArrow, setLeftArrow] = useState<boolean>(false);
  const [rightArrow, setRightArrow] = useState<boolean>(false);

  const filtered: string[] = [];
  users?.forEach((user: any) => {
    if (
      Array.isArray(blocklist) &&
      !blocklist?.find((b: number) => {
        return b === user["id"];
      })
    )
      filtered.push(user);
  });

  useEffect(
    function () {
      function a() {
        if (filtered?.length > page * pageHeight) setRightArrow(() => true);
        if (page > 1) setLeftArrow(() => true);
        if (filtered?.length <= page * pageHeight) setRightArrow(() => false);
        if (page === 1) setLeftArrow(() => false);
      }
      a();
    },
    [page, filtered, blocklist]
  );

  if (!users || !roomname) return;
  else {
    let tmpUsers;
    if (filtered.length <= pageHeight) {
      tmpUsers = filtered;
    } else {
      const startIndex = (page - 1) * pageHeight;
      tmpUsers = filtered.slice(startIndex, startIndex + 8);
    }
    return (
      <>
        <div className="wrp">
          <div className="userlist-header">
            <h4>{isDM ? `DM with ${roomname}` : `Users in ${roomname}`}</h4>

            <button
              onClick={() => setPage(() => page - 1)}
              className={`btn-page ${leftArrow ? "" : "visible"}`}
            >
              &larr;
            </button>
            <button
              onClick={() => setPage(() => page + 1)}
              className={`btn-page ${rightArrow ? "" : "visible"}`}
            >
              &rarr;
            </button>
          </div>

          <ul className="userlist-lists">
            {tmpUsers.map((user: any, i: number) => (
              <ChatRoomUserInfo
                user={user}
                key={i}
                id={id}
                roomInfo={roomInfo}
                setRoomInfo={setRoomInfo}
                roomname={roomname}
                myNickName={myNickName}
                changedID={changedID}
                changedNickName={changedNickName}
                isGameConnected={isGameConnected}
                isDM={isDM}
              />
            ))}
          </ul>
        </div>
      </>
    );
  }
}
