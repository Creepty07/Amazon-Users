import { APIGatewayProxyEvent } from "aws-lambda";
import { verifyAccessToken } from "./jwt";

export interface Caller {
    userId?: string;
    role?: string;
}

// D6: LocalStack no ejecuta el Lambda authorizer, asi que requestContext.authorizer llega vacio.
// En AWS real se usa el contexto del authorizer (prioridad); si falta, se verifica la firma del JWT aqui.
export const getCaller = (event: APIGatewayProxyEvent): Caller => {
    const ctx = event.requestContext.authorizer;
    if (ctx?.userId) {
        return { userId: ctx.userId, role: ctx.role };
    }

    const header = event.headers?.Authorization ?? event.headers?.authorization ?? "";
    try {
        const { userId, role } = verifyAccessToken(header.replace(/^Bearer\s+/i, ""));
        return { userId, role };
    } catch {
        return {};
    }
};
