import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class MatchService {
	constructor (private readonly prisma : PrismaService){}

	async getAllMatchHistory() : Promise<object[]> {
		return this.prisma.matchHistory.findMany({
			select : {
				winner : {
					select : { nickname : true }
				},
				loser : {
					select : { nickname : true }
				},
				createdTime : true
			},
			orderBy : { createdTime : 'desc' }
		});
	}

	async createMatchHistory(data : Prisma.MatchHistoryUncheckedCreateInput) : Promise<object> {
		return await this.prisma.$transaction([
			this.prisma.matchHistory.create({ data }),
			this.prisma.user.update({
				where : { id : data.winnerId },
				data: { score: { increment: 10 } }
			})
		]);
	}
}
