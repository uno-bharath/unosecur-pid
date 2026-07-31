import { ArrayMaxSize, IsArray, IsOptional, IsString } from 'class-validator';

export class SimulateToxicAccessDto {
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(100)
  @IsString({ each: true })
  removePermissions: string[] = [];

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(100)
  @IsString({ each: true })
  removeAssignments: string[] = [];
}
