package com.example.possible.util.helper.dataFormater

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Environment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

object DataFormater {
    fun uriToFile(context: Context, uriString: String): File? {
        return try {
            val uri = Uri.parse(uriString)
            val inputStream: InputStream? = context.contentResolver.openInputStream(uri)

            val file = File(context.cacheDir, "temp_image.jpg")
            val outputStream = FileOutputStream(file)

            inputStream?.copyTo(outputStream)

            outputStream.close()
            inputStream?.close()

            file
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    suspend fun imageUrlToPathInApp(context: Context, imageUrl: String, fileName: String): String? {
        return withContext(Dispatchers.IO) { // تشغيل في Thread منفصل
            val client = OkHttpClient()
            val request = Request.Builder().url(imageUrl).build()

            try {
                val response = client.newCall(request).execute()
                if (!response.isSuccessful) {
                    throw Exception("فشل تحميل الصورة: ${response.code}")
                }

                response.body?.byteStream()?.use { inputStream ->
                    val bitmap = BitmapFactory.decodeStream(inputStream) ?: throw Exception("فشل فك تشفير الصورة")

                    val directory = File(context.getExternalFilesDir(Environment.DIRECTORY_PICTURES), "ProfileImages")
                    if (!directory.exists()) directory.mkdirs()

                    val file = File(directory, "$fileName.jpg")
                    FileOutputStream(file).use { outputStream ->
                        bitmap.compress(Bitmap.CompressFormat.JPEG, 90, outputStream)
                    }

                    return@withContext file.absolutePath
                }
            } catch (e: Exception) {
                e.printStackTrace()
                return@withContext null
            }
        }
    }
     fun imageFileToPathInApp(context: Context, fileName: String): String? {
     return " "
    }


    }