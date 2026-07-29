import { ArrayMaxSize, ArrayNotEmpty, IsArray, IsString } from 'class-validator';

export class SimulateRiskDto {
  @IsArray()
  @ArrayNotEmpty()
  @ArrayMaxSize(25)
  @IsString({ each: true })
  removePermissions!: string[];
}
