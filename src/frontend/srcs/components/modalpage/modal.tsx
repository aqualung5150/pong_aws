import { useEffect, useRef, useState, useContext } from "react";
import { SocketContext } from "@/context/socket";
import "../../../pages/index.css";

export default function ModalBasic({
  setIsOpenModal,
  roomname,
  innerText,
}: {
  setIsOpenModal: any;
  roomname: string;
  innerText: string;
}) {
  // 모달 끄기
  const socket = useContext(SocketContext).chatSocket;
  const [passWord, setPassWord] = useState("");
  const [disabled, setDisabled] = useState(false);

  const closeModal = () => {
    setIsOpenModal(false);
  };
  const modalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // 이벤트 핸들러 함수
    const handler = () => {
      if (!event) return;
      // mousedown 이벤트가 발생한 영역이 모달창이 아닐 때, 모달창 제거 처리
      const target = event.target as HTMLInputElement;
      if (modalRef.current && !modalRef.current.contains(target)) {
        setIsOpenModal(false);
      }
    };

    // 이벤트 핸들러 등록
    document.addEventListener("mousedown", handler);
    // document.addEventListener('touchstart', handler); // 모바일 대응

    return () => {
      // 이벤트 핸들러 해제
      document.removeEventListener("mousedown", handler);
      // document.removeEventListener('touchstart', handler); // 모바일 대응
    };
  });

  const handleSubmit = async (event: any) => {
    setDisabled(true);
    event.preventDefault();
    if (passWord.length < 1) {
      alert("비밀번호를 입력해주세요");
    } else {
      await new Promise((r) => setTimeout(r, 100));
      alert(`${roomname} 방의 비밀번호는 <${passWord}> 입니다.`);
      setIsOpenModal(false);
      socket.emit("sendRoomPass", {
        roomname: roomname,
        password: passWord,
      }); //0813
    }
    setDisabled(false);
  };

  return (
    <div ref={modalRef} className="modal modal-basic">
      <button className="close" onClick={closeModal}>
        X
      </button>
      <p>{innerText}</p>
      <form onSubmit={handleSubmit}>
        <div className="div-form">
          <span>
            {" "}
            <input
              type="text"
              value={passWord}
              onChange={(e) => setPassWord(e.target.value)}
            />
          </span>
          <span>
            <button className="btn-add" type="submit" disabled={disabled}>
              비밀번호 입력
            </button>
          </span>
        </div>
      </form>
    </div>
  );
}
