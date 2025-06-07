import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Level } from 'level';

@Injectable()
export class DbService implements OnModuleInit, OnModuleDestroy {
  private db: Level<string, string>;

  constructor(private readonly configService: ConfigService) { }

  async onModuleInit() {
    const dbPath = this.configService.get<string>('LEVELDB_PATH', './data/auth-db');
    this.db = new Level(dbPath, { valueEncoding: 'json' });
    await this.db.open();
  }

  async onModuleDestroy() {
    if (this.db) {
      await this.db.close();
    }
  }

  async put(key: string, value: any): Promise<void> {
    await this.db.put(key, JSON.stringify(value));
  }

  async get(key: string): Promise<any | null> {
    try {
      const value = await this.db.get(key);
      return JSON.parse(value);
    } catch (error) {
      if (error.notFound) {
        return null;
      }
      throw error;
    }
  }

  async del(key: string): Promise<void> {
    try {
      await this.db.del(key);
    } catch (error) {
      if (!error.notFound) {
        throw error;
      }
    }
  }

  async has(key: string): Promise<boolean> {
    try {
      await this.db.get(key);
      return true;
    } catch (error) {
      if (error.notFound) {
        return false;
      }
      throw error;
    }
  }

  async clear(): Promise<void> {
    await this.db.clear();
  }

  async getByPrefix(prefix: string): Promise<Array<{ key: string; value: any }>> {
    const results: Array<{ key: string; value: any }> = [];

    for await (const [key, value] of this.db.iterator()) {
      if (key.startsWith(prefix)) {
        results.push({
          key,
          value: JSON.parse(value),
        });
      }
    }

    return results;
  }

  async deleteByPrefix(prefix: string): Promise<void> {
    const keysToDelete: string[] = [];

    for await (const [key] of this.db.iterator()) {
      if (key.startsWith(prefix)) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      await this.del(key);
    }
  }

  async count(prefix?: string): Promise<number> {
    let count = 0;

    for await (const [key] of this.db.iterator()) {
      if (!prefix || key.startsWith(prefix)) {
        count++;
      }
    }

    return count;
  }
}
