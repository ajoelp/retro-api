import { User } from '@prisma/client';
import { Request, Response } from 'express';
import { prisma } from '../prismaClient';
import { BOARD_UPDATED_EVENT_NAME } from '../types/socket-events';
import dependencies from '../dependencies';

export class BoardsController {
  async index(req: Request, res: Response) {
    const boards = await prisma.board.findMany();
    return res.json({ boards });
  }

  async fetch(req: Request, res: Response) {
    const { id } = req.params;
    const board = await prisma.board.findFirst({
      where: { id },
      include: {
        columns: true,
      },
    });
    return res.json({ board });
  }

  async create(req: Request, res: Response) {
    const { title, columns } = req.body;

    const board = await prisma.board.create({
      data: {
        title,
        ownerId: (req.user as User).id,
        columns: {
          create: columns.map((column: any, order: number) => ({ title: column, order })),
        },
      },
      include: { columns: true },
    });

    return res.json({ board });
  }

  async update(req: Request, res: Response) {
    const board = await prisma.board.update({
      where: { id: req.params.id },
      data: req.body,
    });

    dependencies.namespaceService.sendEventToBoard(board.id, {
      type: BOARD_UPDATED_EVENT_NAME,
      payload: board,
    });

    return res.json({ board });
  }

  async destroy(req: Request, res: Response) {
    await prisma.board.delete({
      where: { id: req.params.id },
    });
    return res.json({});
  }
}
