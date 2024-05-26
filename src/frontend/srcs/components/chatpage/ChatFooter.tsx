import { useLayoutEffect, useState, useContext, useRef } from "react";
import { SocketContext } from "@/context/socket";
const ChatFooter = ({
  currentRoomName,
  isDM,
  DMtarget,
}: {
  currentRoomName: any;
  isDM: boolean;
  DMtarget: string;
}) => {
  const inputRef = useRef<any>();

  useLayoutEffect(() => {
    if (inputRef.current !== null && inputRef.current !== undefined) {
      inputRef.current.focus();
    }
  }, [currentRoomName, isDM, DMtarget]);

  const socket = useContext(SocketContext).chatSocket;
  const [textareaValue, setTextareaValue] = useState("");
  function handleSubmit(e: any) {
    e?.preventDefault();
    const form = e?.target;
    const formData = new FormData(form);
    const formJson = Object.fromEntries(formData.entries());
    if (!isDM) {
      socket.emit("sendChatMessage", {
        to: currentRoomName,
        body: formJson.textareaContent,
      });
    } else if (isDM) {
      socket.emit("sendDirectMessage", {
        to: DMtarget,
        body: formJson.textareaContent,
      });
    }
    setTextareaValue("");
  }
  function handleSubmit2(e: any) {
    // Prevent the browser from reloading the page
    e?.preventDefault();
    if (textareaValue.length > 500) {
      setTextareaValue("");
      alert("채팅 내용은 500글자 미만");
      return;
    } else if (textareaValue.length === 0) {
      setTextareaValue("");
      alert("채팅 내용을 입력하세요");
      return;
    }
    if (!isDM) {
      socket.emit("sendChatMessage", {
        to: currentRoomName,
        body: textareaValue,
      });
    } else if (isDM) {
      socket.emit("sendDirectMessage", {
        to: DMtarget,
        body: textareaValue,
      });
    }
    setTextareaValue("");
  }
  const handleOnKeyPress = (e: any) => {
    if (e?.isComposing || e?.keyCode === 229) {
      return;
    }

    if (e?.key === "Enter") {
      e?.preventDefault();
      handleSubmit2(e); // Enter 입력이 되면 클릭 이벤트 실행
    }
  };
  return (
    <form
      className="chat-message-footer"
      method="post"
      onSubmit={handleSubmit}
      onKeyDown={handleOnKeyPress}
    >
      <textarea
        name="textareaContent"
        rows={4}
        cols={33}
        className="input2"
        value={textareaValue}
        ref={inputRef}
        onChange={(e) => setTextareaValue(e?.target.value)}
      />
      <button type="submit"> Send </button>
    </form>
  );
};

export default ChatFooter;
