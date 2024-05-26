// import { Socket } from "socket.io-client";

// import * as io from "socket.io-client";
// import React from "react";
// export const socket = io.connect("http://localhost:3002", {
//   query: {
//     id: 1234,
//     nickname: "namkim",
//   },
//   autoConnect: false,
//   auth: {
//     token: "hi",
//   },
// });
// export const SocketContext = React.createContext<Socket>(socket);

import { createContext } from "react";

export type SocketContent = {
    chatSocket: any;
    gameSocket: any;
};

export const SocketContext = createContext<SocketContent>({
    chatSocket: null,
    gameSocket: null,
});