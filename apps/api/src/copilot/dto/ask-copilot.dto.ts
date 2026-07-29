import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class AskCopilotDto {
  @IsString()
  @MinLength(3)
  @MaxLength(500)
  question!: string;

  @IsOptional()
  @IsString()
  identityId?: string;
}
