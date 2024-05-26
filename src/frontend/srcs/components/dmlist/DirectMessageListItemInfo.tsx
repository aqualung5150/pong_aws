import { SocketContext } from "@/context/socket";
import { useContext, useEffect } from "react";

export default function DirectMessageListItemInfo({
  messageInfo,
  myNickName,
  key,
  setDirectMessageList,
  setDirectMessageMap,
  directMessageList,
  directMessageMap,
  currentRoomName,
  isDM,
}: {
  messageInfo: any;
  myNickName: string;
  key: number;
  setDirectMessageList: any;
  setDirectMessageMap: any;
  directMessageList: any;
  directMessageMap: any;
  currentRoomName: string;
  isDM: boolean;
}) {
  const socket = useContext(SocketContext).chatSocket;

  function handleAccept(event: any) {
    const tmpList: any = [];
    directMessageList.map((e: any) => {
      if (e?.[1].data.fromId !== messageInfo?.[1]?.data?.fromId)
        tmpList.push(e);
    });
    let tmpMap = directMessageMap;
    tmpMap.delete(messageInfo?.[1]?.data?.fromId);

    if (event.target.dataset.name !== "x")
      socket.emit("selectDMRoom", { target: messageInfo?.[1]?.data?.from });
    else
      socket.emit("userCheckedDM", {
        targetId: messageInfo?.[1]?.data?.fromId,
      });

    setDirectMessageList(() => tmpList);
    setDirectMessageMap(() => tmpMap);
  }

  if (messageInfo?.length < 2) {
    return;
  } else {
    return (
      <>
        <li onClick={() => handleAccept(event)} className="gameAccept">
          <div className="dmlist-avatar left">
            <img
              src={`http://localhost:80/api/user/${messageInfo?.[1]?.data?.fromId}/photo`}
              width="35"
              height="35"
              alt="avataricon"
            />
          </div>
          <div className="dmlist-nickname" data-name="nick">
            <span>{messageInfo?.[1]?.data?.from}</span>
          </div>
          <div className="dmlist-textInfo" data-name="info">
            {`${
              messageInfo?.[1]?.data?.body?.length >= 14
                ? (messageInfo?.[1]?.data?.body).substr(0, 14) + "..."
                : messageInfo?.[1]?.data?.body
            }`}
          </div>

          <div className="dmlist-button-div" data-name="x">
            <span className="dmlist-button-x" data-name="x">
              {" "}
              X{" "}
            </span>
          </div>
        </li>
      </>
    );
  }
}
