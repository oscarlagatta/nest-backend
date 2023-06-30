import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { InjectModel } from "@nestjs/mongoose";
import * as bcrypt from "bcryptjs";
import { Model, Query } from "mongoose";
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from "./dto";
import { User } from "./entities/user.entity";
import { JwtPayload } from "./interfaces/jwt-payload";
import { LoginResponse } from "./interfaces/login-response";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    @InjectModel(User.name) private userModel: Model<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      // 1 encrypt password
      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData,
      });

      // SAVE USER
      await newUser.save();

      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (e) {
      if (e.code === 11000)
        throw new BadRequestException(`${createUserDto.email} already exists`);
      throw new InternalServerErrorException(
        'Server Error in the Auth Service',
      );
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {

    const user: User = await this.create(registerUserDto);

    return {
      user,
      token: this.getJwtToken({id: user._id})
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('not valid credentials email');
    }


    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('not valid credentials email');
    }

    const { password: _, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    };
  }
  findAll() {
    return this.userModel.find();
  }

  async findUserById(userId: string) {
    const user = await this.userModel.findById(userId);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
