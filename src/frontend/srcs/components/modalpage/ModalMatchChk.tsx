import { useEffect, useRef, useState, useContext } from "react";
import { SocketContext } from "@/context/socket";
import "../../../pages/index.css";

export default function ModalMatchChk({
  setIsOpenModal,
  result,
}: {
  setIsOpenModal: any;
  result: any;
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

  return (
    <div ref={modalRef} className="modal modal-matchchk">
      <div>{JSON.stringify(result, null, 2)}</div>
    </div>
  );
}
