import Logo from "./NavBarLogo";
import Menu from "./NavBarMenu";
import Search from "./NavBarSearch";
// import { SocketContext } from "@/context/socket";
import { useState, useContext } from "react";
export default function NavBar({
  setIsLoading,
  setTmpLoginnickname,
  setLeftHeader,
  setError,
  isGameConnected,
  matchStartCheck,
  handleGameOnOff,
  gameLoad,
}: {
  setIsLoading: any;
  setTmpLoginnickname: any;
  setLeftHeader: any;
  setError: any;
  isGameConnected: boolean;
  matchStartCheck: boolean;
  handleGameOnOff: any;
  gameLoad: any;
}) {
  return (
    <nav className="nav-bar">
      <Search
        setIsLoading={setIsLoading}
        setLeftHeader={setLeftHeader}
        setError={setError}
        isGameConnected={isGameConnected}
        matchStartCheck={matchStartCheck}
        handleGameOnOff={handleGameOnOff}
        gameLoad={gameLoad}
      />
      <Logo />
      <Menu setTmpLoginnickname={setTmpLoginnickname} />
    </nav>
  );
}
