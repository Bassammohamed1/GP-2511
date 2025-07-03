package com.example.possible.util.helper

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody
import java.io.File
import java.io.FileOutputStream

class Drawer(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    private var drawPath: Path = Path()
    private var paint: Paint = Paint()
    private var bitmap: Bitmap? = null
    private var canvas: Canvas? = null
    private val bitmapPaint = Paint(Paint.DITHER_FLAG)

    init {
        paint.apply {
            color = Color.WHITE
            style = Paint.Style.STROKE
            strokeWidth = 50f
            isAntiAlias = true
            strokeJoin = Paint.Join.ROUND
            strokeCap = Paint.Cap.ROUND
        }
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        canvas = Canvas(bitmap!!)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawBitmap(bitmap!!, 0f, 0f, bitmapPaint)
        canvas.drawPath(drawPath, paint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val x = event.x
        val y = event.y
        when (event.action) {
            MotionEvent.ACTION_DOWN -> {
                drawPath.moveTo(x, y)
            }
            MotionEvent.ACTION_MOVE -> {
                drawPath.lineTo(x, y)
            }
            MotionEvent.ACTION_UP -> {
                canvas?.drawPath(drawPath, paint)
                drawPath.reset()
            }
        }
        invalidate()
        return true
    }

    fun getBitmap(): Bitmap? {
        return bitmap
    }

    fun clearCanvas() {
        bitmap?.eraseColor(Color.TRANSPARENT)
        invalidate()
    }


}
