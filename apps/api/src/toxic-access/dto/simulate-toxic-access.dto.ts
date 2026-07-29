import { ArrayMaxSize, ArrayMinSize, IsArray, IsString } from 'class-validator';

export class SimulateToxicAccessDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(100)
  @IsString({ each: true })
  removePermissions!: string[];
}
