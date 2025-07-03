package com.example.possible.ui.tracing

import android.annotation.SuppressLint
import android.content.Context
import android.util.AttributeSet
import android.view.View
import android.graphics.*
import android.view.ViewGroup.LayoutParams
import android.view.MotionEvent
import kotlin.math.sqrt

class TracingView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null
) : View(context, attrs) {
    private var specialCases=ArrayList<String>()
    private lateinit var currentPath :Path
    private var drawing=false
    private var counter=0
    private var tracingName=""
    var completedPaths=ArrayList<Path>()
    private val completedPaint=Paint()
    var pathArray=ArrayList<Path>()
    private val activePaint=Paint()
    private val tracePaint=Paint()
    private val tracedPaint=Paint()
    private val pathMeasure=PathMeasure()
    private val borderPaint=Paint()
    private val thumbPaint=Paint()
    private val thumbRadius = 60f           // نصف قطر الكرة
    private var thumbPos = FloatArray(2)    // موقع الكرة الحالي
    private var pathProgress = 0f
    init {
        specialCases= arrayListOf("D","Y")

        tracePaint.apply {
            color = Color.LTGRAY
            style = Paint.Style.STROKE
            strokeWidth = 80f
            isAntiAlias = true
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }
        borderPaint.apply {
            color = Color.BLACK // Border color (solid black)
            style = Paint.Style.STROKE
            strokeWidth = 5f // Border thickness
            isAntiAlias = true
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }

        activePaint.apply {
            color = Color.YELLOW // Set the desired color (Yellow in this case)
            style = Paint.Style.STROKE
            strokeWidth = 20f // Adjust the thickness of the dots
            isAntiAlias = true
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND

            // Apply DashPathEffect for dotted line
            val intervals = floatArrayOf(0.1f, 50f) // (dot size, gap size)
            pathEffect = DashPathEffect(intervals, 0f)
        }

        // إعدادات الطلاء للأجزاء المكتملة
        tracedPaint.apply {
            color = Color.GREEN
            style = Paint.Style.STROKE
            strokeWidth = 80f
            isAntiAlias = true
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }
        completedPaint.apply {
            color = Color.WHITE
            style = Paint.Style.STROKE
            strokeWidth = 80f
            isAntiAlias = true
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }

        // إعدادات الطلاء للكرة
        thumbPaint.apply {
            color = Color.RED
            style = Paint.Style.FILL
            isAntiAlias = true
        }
   }
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        // رسم المسار الأساسي باللون الرمادي الفاتح
        for(path in pathArray){
            canvas.drawPath(path, tracePaint)
        }


        canvas.drawPath(getTracedPath(), tracedPaint)
        for (path in completedPaths) {
            canvas.drawPath(path, completedPaint)
            if(checkAllPathsCompleted()){
                drawing=false
                invalidate()
            }
        }

        // رسم الكرة في موقعها الحالي
        // بدء الكرة من بداية المسار

        if(drawing){
            canvas.drawPath(getActivePath(),borderPaint)
            canvas.drawPath(getActivePath(), activePaint)
            canvas.drawCircle(thumbPos[0], thumbPos[1], thumbRadius, thumbPaint)}
        invalidate()

    }
    private fun getActivePath(): Path {
        return currentPath
    }
    private fun getTracedPath(): Path {
        val tracedPath = Path()
        pathMeasure.getSegment(0f, pathProgress * pathMeasure.length, tracedPath, true)
        return tracedPath
    }

    private fun changePath(index:Int){
        currentPath=pathArray[index]
        pathMeasure.setPath(currentPath, false)
        pathMeasure.getPosTan(0f, thumbPos, null)
        pathProgress = 0f
        invalidate()
    }
    private var isDragging = false  // متغير لتحديد إذا كان المستخدم يسحب الكرة
    private fun addCompletedPath(path: Path) {
        completedPaths.add(path)
    }
    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        val touchX = event.x
        val touchY = event.y
        if(isFullyTraced()){
            isDragging=false
            if(counter<pathArray.size){
                addCompletedPath(currentPath)
                    counter++
                }
            if(counter<pathArray.size){
                changePath(counter)
                if(tracingName.isNotEmpty()){
                    if(tracingName !in specialCases)
                    {
                        isDragging=true
                    }
                }
        }}


        when (event.action) {
            MotionEvent.ACTION_DOWN -> {
                // التحقق مما إذا كانت اللمسة على الكرة لبدء السحب
                val dx = touchX - thumbPos[0]
                val dy = touchY - thumbPos[1]
                val distance = sqrt((dx * dx + dy * dy).toDouble())

                if (distance <= thumbRadius) {
                    isDragging = true
                    return true
                }
            }

            MotionEvent.ACTION_MOVE -> {
                // متابعة الحركة إذا كان المستخدم يسحب الكرة
                if (isDragging) {
                    val (nearestProgress, nearestPos) = getNearestPointOnPath(touchX, touchY)

                    // التحقق من أن اللمسة على المسار وقريبة من الكرة
                    if (nearestProgress > pathProgress && distanceToPath(touchX, touchY) <= thumbRadius) {
                        pathProgress = nearestProgress
                        thumbPos = nearestPos
                        invalidate()  // تحديث الرسم على الشاشة
                    }
                }
            }

            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                // إنهاء السحب عند رفع الإصبع
                isDragging = false
            }
        }
        return true
    }

    // دالة لحساب المسافة بين نقطة اللمس وأقرب نقطة على المسار
    private fun distanceToPath(touchX: Float, touchY: Float): Float {
        var closestDistance = Float.MAX_VALUE

        // التكرار عبر المسار لحساب المسافة
        for (i in 0..1000) {
            val progress = i / 1000f * pathMeasure.length
            val pos = FloatArray(2)
            pathMeasure.getPosTan(progress, pos, null)

            val dx = touchX - pos[0]
            val dy = touchY - pos[1]
            val distance = Math.sqrt((dx * dx + dy * dy).toDouble()).toFloat()

            if (distance < closestDistance) {
                closestDistance = distance
            }
        }
        return closestDistance
    }

    private fun getNearestPointOnPath(touchX: Float, touchY: Float): Pair<Float, FloatArray> {
        val pathLength = pathMeasure.length
        var closestDistance = Float.MAX_VALUE
        var closestPos = FloatArray(2)
        var closestProgress = 0f

        for (i in 0..1000) {
            val progress = i / 1000f * pathLength
            val pos = FloatArray(2)
            pathMeasure.getPosTan(progress, pos, null)

            val dx = touchX - pos[0]
            val dy = touchY - pos[1]
            val distToTouch = dx * dx + dy * dy

            if (distToTouch < closestDistance) {
                closestDistance = distToTouch
                closestPos = pos
                closestProgress = progress / pathLength
            }
        }
        return Pair(closestProgress, closestPos)
    }
    fun checkAllPathsCompleted(): Boolean {

        return (completedPaths.size == pathArray.size)
    }
    private fun isFullyTraced(): Boolean {
        val progress = pathProgress * pathMeasure.length
        val pathLength = pathMeasure.length
        return (pathLength - progress)<=1f
    }
    fun setNewPathArray(paths: ArrayList<Path>, name:String) {
        pathArray= arrayListOf()
        tracingName=name
        completedPaths= arrayListOf()
        pathArray = paths
        if (pathArray.isNotEmpty()) {
            currentPath = pathArray[0]
            pathMeasure.setPath(currentPath,false)
            pathMeasure.getPosTan(0f, thumbPos, null)
            pathProgress = 0f
            counter = 0
            drawing = true
            invalidate()
        }
    }
    @SuppressLint("DrawAllocation")
    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
        super.onLayout(changed, left, top, right, bottom)

        // هنا سيتم تحديد المكان داخل الفراجمنت
        val width = right - left
        val height = bottom - top

        // تغيير حجم الكستم فيو ليأخذ الحجم المتاح في الفراجمنت
        layoutParams = LayoutParams(width, height)
    }


}