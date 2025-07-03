package com.example.possible.repo.local
import android.graphics.Path
object TracingPaths {


    private lateinit var paths:ArrayList<Path>
    fun getLetterPaths(index:Int):ArrayList<Path>{
        paths = when(index){
            0 -> getA()
            1 -> getB()
            2 -> getC()
            3 -> getD()
            4 -> getE()
            5 -> getF()
            6 -> getG()
            7 -> getH()
            8 -> getI()
            9 -> getJ()
            10 -> getK()
            11 -> getL()
            12 -> getM()
            13 -> getN()
            14 -> getO()
            15 -> getP()
            16 -> getQ()
            17 -> getR()
            18 -> getS()
            19 -> getT()
            20 -> getU()
            21 -> getV()
            22 -> getW()
            23 -> getX()
            24 -> getY()
            25 -> getZ()
            else -> arrayListOf()}
        return paths
    }
    fun getNumberPaths(index:Int):ArrayList<Path>{
        paths = when(index){
            0 -> getZero()
            1 -> getOne()
            2 -> getTwo()
            3 -> getThree()
            4 -> getFour()
            5 -> getFive()
            6 -> getSix()
            7 -> getSeven()
            8 -> getEight()
            9 -> getNine()
            10 -> getTen()
            else -> arrayListOf()}
        return paths
        }



     private fun getA():ArrayList<Path>{
        paths = arrayListOf()
         addPath(setPath(Path(), 300f, 100f, 100f, 500f))
         addPath(setPath(Path(), 300f, 100f,500f, 500f))
         addPath(setPath(Path(), 200f, 300f, 400f, 300f))
        return paths
    }

    private fun getB():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 200f, 100f, 200f, 700f))
        addPath(setPathByCubic(Path(), 200f, 100f, 600f, 10f,500f,350f, 200f, 350f))
        addPath(setPathByCubic(Path(), 200f,350f, 600f, 350f,600f,690f,  200f, 700f))
       return paths
    }

    private fun getC():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setArchPath(Path(),50f,50f,450f,550f,-45f,-265f))
        return paths
    }

    private fun getD():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPathByCubic(Path(), 100f, 100f, 550f, 130f,550f,470f, 100f, 600f))
        addPath(setPath(Path(), 100f, 100f, 100f, 600f))
         return paths
    }
    private fun getE():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 200f, 100f, 600f)) //vertical line
        addPath(setPath(Path(), 100f, 200f, 400f, 200f)) //horizontal line 1
        addPath(setPath(Path(), 100f, 600f, 400f, 600f)) //horizontal line 3
        addPath(setPath(Path(), 100f, 400f, 400f, 400f)) //horizontal line 2
        return paths
    }
    private fun getF():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 400f, 200f, 100f, 200f)) //horizontal line 1
        addPath(setPath(Path(), 100f, 200f, 100f, 600f)) //vertical line
        addPath(setPath(Path(), 400f, 400f, 100f, 400f)) //horizontal line 2
        return paths
    }
    private fun getG():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setArchPath(Path(),50f,50f,450f,550f,-45f,-300f))
        addPath(setPath(Path(), 440f,360f,250f, 360f)) //vertical line
        return paths
    }
    private fun getH():ArrayList<Path>{
        val paths= arrayListOf(
        setPath(Path(), 100f, 100f, 100f, 600f),
        setPath(Path(), 400f, 100f, 400f, 600f),
        setPath(Path(), 100f, 350f, 400f, 350f)
        )
        return paths
        }
    private fun getI():ArrayList<Path>{
        val paths= arrayListOf(
        setPath(Path(), 200f, 100f, 200f, 600f),
        setPath(Path(), 100f, 100f, 300f, 100f),
        setPath(Path(), 100f, 600f, 300f, 600f)
        )
        return paths
    }
    private fun getJ():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 400f, 100f, 400f, 600f))
        addPath(setPathByCubic(Path(),400f,600f,400f,790f,90f,790f,100f,550f))
        return paths
    }
    private fun getK():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 100f, 700f))
        addPath(setPath(Path(), 400f, 100f, 100f, 400f))
        addPath(setPath(Path(), 100f, 400f, 400f, 700f))
        return paths
    }
    private fun getL():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 100f, 600f))
        addPath(setPath(Path(), 100f, 600f, 400f, 600f))
        return paths

    }
    private fun getM():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 600f, 150f, 100f))
        addPath(setPath(Path(), 150f, 100f, 300f, 350f))
        addPath(setPath(Path(), 300f, 350f, 450f, 100f))
        addPath(setPath(Path(), 450f, 100f, 500f, 600f))
        return paths
    }
    private fun getN():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 600f, 100f, 100f))
        addPath(setPath(Path(), 100f, 100f, 450f, 600f))
        addPath(setPath(Path(), 450f, 600f, 450f, 100f))
        return paths
    }
    private fun getO():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setArchPath(Path(),50f,50f,450f,550f,0f,-351f))
        return paths
    }
    private fun getP():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 200f, 100f, 200f, 700f))
        return paths
    }
    private fun getQ():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setArchPath(Path(), 50f, 50f, 450f, 550f, 0f, -351f))
        addPath(setPath(Path(), 250f, 300f, 500f, 600f))
        return paths
    }
    private fun getR():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 200f, 100f, 200f, 700f))
        addPath(setPathByCubic(Path(),200f,100f,500f,105f,500f,395f,200f,400f))
        addPath(setPath(Path(), 200f, 400f, 500f, 700f))
        return paths
    }
    private fun getS():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setArchPath(Path(),200f,100f,500f,350f,-45f,-230f))
        addPath(setArchPath(Path(),200f,350f,500f,600f,-90f,230f))
        return paths
    }
    private fun getT():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPath(Path(), 300f, 100f, 300f, 600f))
        addPath(setPath(Path(), 100f, 100f, 500f, 100f))
        return paths
    }
    private fun getU():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setPathByCubic(Path(), 100f, 100f,70f,600f,430f,600f, 400f, 100f))
        return paths
    }
    private fun getV():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 300f, 600f))
        addPath(setPath(Path(), 300f, 600f, 500f, 100f))
        return paths
    }
    private fun getW():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 50f, 100f, 100f, 600f))
        addPath(setPath(Path(), 100f, 600f, 250f, 300f))
        addPath(setPath(Path(), 250f, 300f, 400f, 600f))
        addPath(setPath(Path(), 400f, 600f, 450f, 100f))
        return paths
    }
    private fun getX():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 400f, 600f))
        addPath(setPath(Path(), 400f, 100f, 100f, 600f))
        return paths

    }
    private fun getY():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 300f, 350f))
        addPath(setPath(Path(), 500f, 100f, 300f, 350f))
        addPath(setPath(Path(), 300f, 350f, 300f, 600f))
        return paths
    }
    private fun getZ():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 500f, 100f))
        addPath(setPath(Path(), 500f, 100f, 100f, 600f))
        addPath(setPath(Path(), 100f, 600f, 500f, 600f))
        return paths
    }
    private fun getZero():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setArchPath(Path(),50f,50f,450f,550f,0f,-351f))
        return paths
    }
    private fun getOne():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 300f, 100f, 300f, 700f))
        addPath(setPath(Path(), 300f, 100f, 200f, 200f))
        return paths
    }
    private fun getTwo():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPathByCubic(Path(), 100f, 150f, 150f, 0f,700f,180f,100f,500f))
        addPath(setPath(Path(), 100f, 500f, 400f, 500f))
        return paths
    }
    private fun getThree():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 400f, 100f))
        addPath(setPath(Path(), 400f, 100f, 100f, 300f))
        addPath(setPathByCubic(Path(), 100f, 300f,500f,180f,500f,590f, 100f, 600f))
         return paths
    }
    private fun getFour():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 300f, 100f, 50f, 400f))
        addPath(setPath(Path(), 50f, 400f, 400f, 400f))
        addPath(setPath(Path(), 300f, 100f, 300f, 600f))
        return paths
    }
    private fun getFive():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 400f, 100f, 110f, 100f))
        addPath(setPath(Path(), 110f, 100f, 90f, 300f))
        addPath(setPathByCubic(Path(), 90f, 300f,500f,200f,400f,600f, 100f,600f))
         return paths
    }
    private fun getSix():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPathByCubic(Path(),500f,100f,100f,0f,100f,500f,300f,600f))
        addPath(setPathByCubic(Path(), 300f, 600f, 600f,700f,600f,200f, 200f,400f))
        return paths
    }
    private fun getSeven():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 100f, 100f, 500f, 100f))
        addPath(setPath(Path(), 500f, 100f, 100f, 600f))
        return paths
    }
    private fun getEight():ArrayList<Path> {
        paths = arrayListOf()
        addPath(setArchPath(Path(),200f,100f,500f,350f,70f,-320f))
        addPath(setArchPath(Path(),200f,350f,500f,600f,-90f,320f))
        return paths
    }
    private fun getNine():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPathByCubic(Path(),300f,100f,450f,150f,300f,600f,300f,600f))
        addPath(setPathByCubic(Path(), 300f, 100f,0f,50f,100f,400f, 350f, 300f))
        return paths
    }
    private fun getTen():ArrayList<Path>{
        paths = arrayListOf()
        addPath(setPath(Path(), 150f, 100f, 150f, 700f))
        addPath(setPath(Path(), 150f, 100f, 50f, 150f))
        addPath(setArchPath(Path(),250f,250f,500f,650f,0f,-351f))

        return paths
    }









    private fun addPath(path:Path){
        paths.add(path)
    }
    private fun setArchPath(path:Path, mx:Float, my:Float, ex:Float, ey:Float, startAngle:Float, sweepAngle:Float):Path{
        path.apply {
            arcTo(mx,my,ex,ey,startAngle,sweepAngle,true)
        }
        return path
    }

    private fun setPathByCubic(path: Path, mx: Float, my: Float, cx1: Float, cy1: Float, cx2: Float, cy2: Float, ex: Float, ey: Float
    ): Path {
        path.apply {
            moveTo(mx, my)
            cubicTo(cx1, cy1, cx2, cy2, ex,ey)
        }
        return path
    }

    private fun setPath(path:Path, mx:Float, my:Float, ex:Float, ey:Float):Path{
        path.apply {
            moveTo(mx, my)
            lineTo(ex, ey)
        }
        return path
    }






}
