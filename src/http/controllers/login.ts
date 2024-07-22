import { z } from 'zod'
import { FastifyRequest, FastifyReply } from 'fastify'
import { prisma } from '@/lib/prisma'
import { compare } from 'bcryptjs'

export async function login(request: FastifyRequest, reply: FastifyReply) {
  const registerBodySchema = z.object({
    email: z.string(),
    password: z.string().min(6),
  })

  const { email, password } = registerBodySchema.parse(request.body)

  const user = await prisma.user.findFirst({
    where:{
      email: email
    }
  })

  if(!user){
    return reply.status(404).send('Email ou senha inválidos')
  }

    const passwordMatch = await compare(password, user.password_hash)
  
    if(!passwordMatch){
        return reply.status(404).send('Email ou senha inválidos')
    }

    const token = await reply.jwtSign({},{
        
        sign:{
            sub: user.id,
        }
    })

    const refreshToken = await reply.jwtSign({},{
        sign:{
            sub: user.id,
        }
    })


    return {
        user,
        token
    }
}
