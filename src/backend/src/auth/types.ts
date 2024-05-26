
export type JwtPayload = {
    id: number;
    name: string;
    email: string;
}

export type Login = {
    id: number;
    name: string;
    email: string;
    nickname: string;
    is2faEnabled: boolean,
    isNewUser: boolean ;
}