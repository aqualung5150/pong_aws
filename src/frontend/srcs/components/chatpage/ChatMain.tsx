import React, { useEffect, useState, useRef, useContext } from "react";
import ChatHeader from "./ChatHeader";
import ChatBody from "./ChatBody";
import ChatFooter from "./ChatFooter";
import { SocketContext } from "@/context/socket";

const ChatMain = ({
  roomInfo,
  setRoomInfo,
  currentRoomName,
  setCurrentRoomName,
  myNickName,
  messages,
  setMessages,
  blocklist,
  gameLoad,
  isDM,
  setIsDM,
  setDMTargetId,
}: {
  roomInfo: any;
  setRoomInfo: any;
  currentRoomName: string;
  setCurrentRoomName: any;
  myNickName: string;
  messages: any;
  setMessages: any;
  blocklist: string[];
  gameLoad: boolean;
  isDM: boolean;
  setIsDM: any;
  setDMTargetId: any;
}) => {
  const [DMtarget, setDMtarget] = useState<string>("");
  const [roomState, setRoomState] = useState<string>("");
  const lastMessageRef = useRef<null | HTMLElement>(null);
  const socket = useContext(SocketContext).chatSocket;

  useEffect(() => {
    function sendCurrRoomInfo(result: any) {
      setRoomInfo(() => result);
      setCurrentRoomName(() => result.roomname);
      setMessages(() => result.messages);
      setIsDM(() => false);
      setRoomState(() => (result?.isPrivate ? "Private" : "Public"));
      setDMTargetId(() => -3);
    }

    function sendDMRoomInfo(target: any, targetId: number, messages: any) {
      socket.emit("userCheckedDM", { targetId: targetId });
      setCurrentRoomName(() => target);
      setMessages(() => messages);
      setIsDM(() => true);
      setDMtarget(() => target);
      setDMTargetId(() => targetId);
    }
    socket.on("sendCurrRoomInfo", sendCurrRoomInfo);
    socket.on("sendDMRoomInfo", sendDMRoomInfo);
    return () => {
      socket.off("sendCurrRoomInfo", sendCurrRoomInfo);
      socket.off("sendDMRoomInfo", sendDMRoomInfo);
    };
  }, [
    currentRoomName,
    messages,
    setMessages,
    setCurrentRoomName,
    setRoomInfo,
    socket,
  ]);

  useEffect(() => {
    lastMessageRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <div className={`chat-main ${gameLoad ? "hidden" : ""}`}>
      <ChatHeader
        roomInfo={roomInfo}
        roomState={roomState}
        setRoomState={setRoomState}
        myNickName={myNickName}
        isDM={isDM}
        currentRoomName={currentRoomName}
      />

      <div className="chat-message-main">
        <ChatBody
          blocklist={blocklist}
          messages={messages}
          // typingStatus={typingStatus}
          lastMessageRef={lastMessageRef}
          myNickName={myNickName}
        />
        <ChatFooter
          isDM={isDM}
          DMtarget={DMtarget}
          currentRoomName={currentRoomName}
        />
      </div>
    </div>
  );
};

export default ChatMain;
