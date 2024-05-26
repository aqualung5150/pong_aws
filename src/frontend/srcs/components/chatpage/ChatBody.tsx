import { useState, useContext, useEffect } from "react";
import Image from "next/image";
import { SocketContext } from "@/context/socket";

const ChatBody = ({
  messages,
  blocklist,
  // typingStatus,
  lastMessageRef,
  myNickName,
}: {
  messages: any;
  blocklist: any;
  // typingStatus: string;
  lastMessageRef: any;
  myNickName: string;
}) => {
  // const socket = useContext(SocketContext).chatSocket;
  const [imgURL, setImgURL] = useState<string | undefined>("");
  const socket = useContext(SocketContext).chatSocket;
  useEffect(() => {}, []);
  useEffect(() => {
    function reloadAvatar(userId: number) {
      console.log(
        "in useEffect my updateUserAvataer ",
        userId,
        String(new Date())
      );
      setImgURL(() => String(new Date()));
    }

    if (socket) {
      socket.on("updateUserAvatar", reloadAvatar);
    }
    return () => {
      if (socket) {
        socket.off("updateUserAvatar", reloadAvatar);
      }
    };
  }, [socket]);
  const filteredMessage: any[] = [];

  function filter(messages: any) {
    messages?.forEach((message: any) => {
      if (
        Array.isArray(blocklist) &&
        !blocklist?.find((b: any) => {
          return b === message.fromId;
        })
      )
        filteredMessage.push(message);
    });
  }
  filter(messages);

  if (messages?.length === 0) return;

  return (
    <div className="chat-message-body">
      {filteredMessage?.map((message: any, i: number) =>
        message["from"] === myNickName ? (
          <div
            className={`sender-${
              message["from"] === myNickName ? "right" : "left"
            }`}
            key={i}
          >
            <div>
              <p className="message-sender">{message.body}</p>
            </div>
            <div className="message-sender-low">
              <div className="message-sender-at">
                {new Date(message.at).toDateString()}
              </div>
            </div>
          </div>
        ) : (
          <div
            className={`sender-${
              message["from"] === myNickName ? "right" : "left"
            }`}
            key={i}
          >
            <div className="message-recipient-avatar">
              <img
                src={`http://localhost:80/api/user/${message?.fromId}/photo?timestamp=${imgURL}`}
                width="35"
                height="35"
                alt="usericon"
              />
              {/* <Image
                src={`http://localhost:80/api/user/${message?.fromId}/photo?timestamp=${imgURL}`}
                width="35"
                height="35"
                alt="usericon"
              /> */}
              {/* <Image
                src={`http://localhost/api/user/${message?.fromId}/photo`}
                width="35"
                height="35"
                alt="usericon"
              /> */}
            </div>
            <div>
              <p className="message-recipient">{message.body}</p>
            </div>
            <div className="message-recipient-low">
              <div className="message-recipient-nick">{message.from}</div>
              <div className="message-recipient-at">
                {new Date(message.at).toDateString()}
              </div>
            </div>
          </div>
        )
      )}
      <div ref={lastMessageRef} />
    </div>
  );
};

export default ChatBody;

/*
소켓 이벤트를 받을때마다 렌더링이 이뤄지는 곳 && api 요청이 필요한 곳
위 조건에 해당하는 모든 곳에 refresh 로직 적용

!! 바깥에서 한번에 할 수 없을까 => {
  1. updateUserAvatar를 App.tsx에서 받는다면 가능
  2.
}
*/
