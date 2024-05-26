export default function ModalOverlay({ isOpenModal }: { isOpenModal: any }) {
  return <div className={`overlay ${!isOpenModal ? "hidden" : ""}`}></div>;
}
