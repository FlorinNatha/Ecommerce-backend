import { NextFunction, Request, Response } from "express"
import { prismaCilent } from "..";
import { compareSync, hashSync } from "bcrypt";
import * as jwt from 'jsonwebtoken';
import { JWT_SECRET } from "../secrets";
import { BadRequestException } from "../exceptions/bad-requests";
import { ErrorCode } from "../exceptions/root";


export const signup = async (req: Request, res: Response , next: NextFunction) => {
    const {email, password, name} = req.body; //body ekn gnnwa user type karpu details

    let user = await prismaCilent.user.findFirst({where: {email}}) //already signup d balnwa user
    if(user) {
        next (new BadRequestException('User already exists!', ErrorCode.USER_ALREADY_EXISTS)) // already signup nm error ek denwa
    }
    user = await prismaCilent.user.create({ // signup wela nththm befor create karnwa e new userwa
        data:{
            name,
            email,
            password: hashSync(password, 10)
        }
    })
    res.json(user)
}

export const login = async (req: Request, res: Response) => {
    const {email, password} = req.body;

    let user = await prismaCilent.user.findFirst({where: {email}})
    if(!user){
        throw Error('User does not exists!')  //user eknk e mail ekat nththm error ekk denwa
    }
    if(!compareSync(password, user.password)){ //compaire karnwa login ekedi dipu password eki database eke tina password eki match ewnwad kiyala
        throw Error('Incorrect password!')
    }
    const token = jwt.sign({
        userId: user.id
    }, JWT_SECRET)

    res.json({user, token})
}