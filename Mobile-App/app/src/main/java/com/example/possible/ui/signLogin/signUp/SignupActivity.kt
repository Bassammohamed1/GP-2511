package com.example.possible.ui.signLogin.signUp

import android.Manifest.permission.READ_EXTERNAL_STORAGE
import android.Manifest.permission.READ_MEDIA_IMAGES
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.view.View
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.widget.addTextChangedListener
import androidx.lifecycle.ViewModelProvider
import com.example.possible.databinding.ActivitySignupBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.ui.splach.AnimationActivity
import com.example.possible.util.helper.dataFormater.DataFormater
import com.example.possible.util.helper.dataManager.AppDataManager
import java.io.File

class SignupActivity : AppCompatActivity() {
    private lateinit var binding: ActivitySignupBinding
    private lateinit var pref: SharedPref
    private var imageUriString: String = ""
    private lateinit var imageFile: File
    private lateinit var viewModel: SignupViewModel

    companion object {
        private const val GALLERY_REQUEST_CODE = 101
        private const val PERMISSION_REQUEST_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivitySignupBinding.inflate(layoutInflater)
        viewModel = ViewModelProvider(this)[SignupViewModel::class.java]
        setContentView(binding.root)

        pref = SharedPref(this)
        checkAndRequestPermissions()
        setControllers()
    }

    // إعداد الأحداث للمكونات
    @SuppressLint("IntentReset")
    private fun setControllers() {
        binding.sign.setOnClickListener { onSignUp() }
        binding.chooseImage.setOnClickListener { openGallery() }
        binding.emailET.addTextChangedListener {
            binding.emailLayout.error=null
        }
        binding.passwordET.addTextChangedListener {
            binding.passLayout.error=null
        }
    }

    // فتح المعرض لاختيار صورة
    private fun openGallery() {
        val intent = Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI).apply {
            type = "image/*"
        }
        startActivityForResult(intent, GALLERY_REQUEST_CODE)
    }

    // التحقق من الصلاحيات وطلبها إن لزم الأمر
    private fun checkAndRequestPermissions() {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(READ_MEDIA_IMAGES)
        } else {
            arrayOf(READ_EXTERNAL_STORAGE)
        }
        ActivityCompat.requestPermissions(this, permissions, PERMISSION_REQUEST_CODE)
    }

    // التعامل مع نتيجة طلب الصلاحيات
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE && grantResults.isNotEmpty() && grantResults[0] != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    // التعامل مع نتيجة اختيار الصورة
    @Deprecated("Use Activity Result API instead")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == GALLERY_REQUEST_CODE && resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                binding.profileImage.setImageURI(uri)
                imageUriString = uri.toString()
            }
        }
    }

    // تنفيذ عملية التسجيل
    private fun onSignUp() {
        if (validateInput()&& imageFound()) {
            sendDataForApi()
            binding.nextBtn.setOnClickListener { goToAnimation() }
        }
        else {
            Toast.makeText(this, "❌ Please fill all fields and choose an image.", Toast.LENGTH_SHORT).show()
        }
    }
    private fun imageFound(): Boolean {
        return imageUriString.isNotEmpty()
    }
    // التحقق من صحة البيانات المدخلة
    private fun validateInput(): Boolean {
        return binding.name.text.isNotEmpty() && binding.emailET.text!!.isNotEmpty() && binding.passwordET.text!!.isNotEmpty()
    }

    // إرسال البيانات إلى API (يجب تنفيذها لاحقًا)
    private fun sendDataForApi() {
        imageFile = DataFormater.uriToFile(this, imageUriString)!!
        viewModel.signUpUserSync(
            binding.name.text.toString(),
            binding.emailET.text.toString(),
            binding.passwordET.text.toString(),
            AppDataManager.getRoleForApi(pref),
            imageFile,
            this
            ,binding
        ) { showSuccessMessage() }
    }

    // عرض رسالة نجاح
    private fun showSuccessMessage() {
        binding.createdView.visibility = View.VISIBLE
        binding.createdView.animate().alpha(0f).setDuration(0).start()
        binding.createdView.animate().alpha(1f).setDuration(1000).start()
    }

    // الانتقال إلى شاشة الـ Animation بعد النجاح
    private fun goToAnimation() {
        startActivity(Intent(this, AnimationActivity::class.java))
        finish()
    }
}

