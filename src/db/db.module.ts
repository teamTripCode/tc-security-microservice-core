import { Module } from '@nestjs/common';
import { DbService } from './db.service';
import { TokenStorageService } from './services/token-storage.service';
import { ResetTokenStorageService } from './services/reset-token-storage.service';
import { UserCacheService } from './services/user-cache.service';

@Module({
  providers: [
    DbService,
    TokenStorageService,
    ResetTokenStorageService,
    UserCacheService
  ],
  exports: [
    DbService,
    TokenStorageService,
    ResetTokenStorageService,
    UserCacheService
  ]
})
export class DbModule { }
