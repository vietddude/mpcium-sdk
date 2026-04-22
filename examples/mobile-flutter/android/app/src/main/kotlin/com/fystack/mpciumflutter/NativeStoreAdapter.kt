package com.fystack.mpciumflutter

import android.content.Context
import mobile.StoreAdapter
import net.sqlcipher.Cursor
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SQLiteOpenHelper

class NativeStoreAdapter(context: Context) : StoreAdapter {
    private val helper = KvDbHelper(context.applicationContext)
    private val passphrase = SQLiteDatabase.getBytes("mpcium-mobile-v1".toCharArray())

    init {
        SQLiteDatabase.loadLibs(context)
    }

    override fun get(key: String): String {
        val db = helper.getReadableDatabase(passphrase)
        val cursor: Cursor = db.rawQuery("SELECT value FROM kv WHERE k = ?", arrayOf(key))
        cursor.use {
            if (!it.moveToFirst()) return ""
            return it.getString(0) ?: ""
        }
    }

    override fun put(key: String, valueBase64: String) {
        val db = helper.getWritableDatabase(passphrase)
        db.execSQL(
            "INSERT OR REPLACE INTO kv(k, value) VALUES(?, ?)",
            arrayOf(key, valueBase64),
        )
    }

    override fun delete(key: String) {
        val db = helper.getWritableDatabase(passphrase)
        db.execSQL("DELETE FROM kv WHERE k = ?", arrayOf(key))
    }

    private class KvDbHelper(context: Context) :
        SQLiteOpenHelper(context, "mpcium_flutter.db", null, 1) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)",
            )
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
    }
}
