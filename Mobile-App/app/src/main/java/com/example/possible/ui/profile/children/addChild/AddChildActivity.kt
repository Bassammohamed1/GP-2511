package com.example.possible.ui.profile.children.addChild

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View.GONE
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import com.example.possible.R
import com.example.possible.databinding.ActivityAddChildBinding
import com.example.possible.model.Child
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.report.ReportActivity
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AddChildActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAddChildBinding
    private lateinit var db: LocalRepoImp
    private var name = ""
    private var gender = 1
    private var age = 1
    private var imageUri: Uri? = null
    private var difficulty = ""
    private var readingRate = 0
    private var writingRate = 0
    private var latestReadingDay: String? = null
    private var latestWritingDay : String? = null
    private var readingDays = 0
    private var writingDays = 0
    private var dateOfCreation = ""
   // private val ADD_MODE = "add"
    private val EDIT_MODE = "edit"
    private var mode = ""
    private var childId = 0
    private var child: Child? = null
    private lateinit var pref:SharedPref
    private lateinit var viewModel: AddChildViewModel

    private companion object {
        const val GALLERY_REQUEST_CODE = 101
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAddChildBinding.inflate(layoutInflater)
        checkAndRequestPermissions()
        viewModel = ViewModelProvider(this)[AddChildViewModel::class.java]
        db = LocalRepoImp(this)
        pref = SharedPref(this)
        setContentView(binding.root)
        if(pref.getRole()=="Specialist"){
            binding.doneBtn.visibility=GONE
        }
        mode = intent.getStringExtra("mode")!!
        if (mode == EDIT_MODE){
            childId = intent.getIntExtra("childId", 1)
            getTheChildToView(childId)
        }
        setupUI()

        checkStoragePermission()
    }




    private fun checkStoragePermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), PERMISSION_REQUEST_CODE
                )
            }
        }
    }

    private fun setupUI() {
        setupNumberPicker()
        setupGenderPicker()
        binding.doneBtn.setOnClickListener {
            if (mode == EDIT_MODE) {
                validateAndUpdateChild()
            }
            else {
                validateAndSaveChild()
            }

        }
        binding.report.setOnClickListener {
            val intent = Intent(this, ReportActivity::class.java)
            intent.putExtra("childId", childId)
            startActivity(intent)
        }

        binding.backArrowIV.setOnClickListener { finish() }
        setupImagePicker()
    }
    private fun setupImagePicker(){
        binding.profileIV.setOnClickListener {
            val intent = Intent(Intent.ACTION_PICK)
            intent.type = "image/*"
            startActivityForResult(intent, GALLERY_REQUEST_CODE)
        }

    }

    private fun setupNumberPicker() {
        binding.agePicker.minValue = 1
        binding.agePicker.maxValue = 15
        binding.agePicker.setOnValueChangedListener { _, _, newVal -> age = newVal }

    }

    private fun setupGenderPicker() {
        binding.radioGroup.setOnCheckedChangeListener { _, checkedId ->
            gender = if (checkedId == R.id.femaleRB) 0 else 1
            Log.d("GenderValue", gender.toString())

        }

    }


    private val PERMISSION_REQUEST_CODE = 100

    private fun checkAndRequestPermissions() {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(Manifest.permission.READ_MEDIA_IMAGES)
        } else {
            arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
        }

        // فحص الأذونات دفعة واحدة وطلبها إذا لزم الأمر
        ActivityCompat.requestPermissions(this, permissions, PERMISSION_REQUEST_CODE)
    }


    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Toast.makeText(this, "Permission granted", Toast.LENGTH_SHORT).show()
            } //else {
                //Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show()
            //}
        }
    }


    @Deprecated("This method has been deprecated in favor of using the Activity Result API\n      which brings increased type safety via an {@link ActivityResultContract} and the prebuilt\n      contracts for common intents available in\n      {@link androidx.activity.result.contract.ActivityResultContracts}, provides hooks for\n      testing, and allow receiving results in separate, testable classes independent from your\n      activity. Use\n      {@link #registerForActivityResult(ActivityResultContract, ActivityResultCallback)}\n      with the appropriate {@link ActivityResultContract} and handling the result in the\n      {@link ActivityResultCallback#onActivityResult(Object) callback}.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == GALLERY_REQUEST_CODE && resultCode == RESULT_OK && data != null) {
            val selectedImageUri: Uri? = data.data
            if (selectedImageUri != null) {
                // تعيين الصورة في ImageView
                binding.profileIV.setImageURI(selectedImageUri)
                imageUri=selectedImageUri

            }
        }
    }


    private fun animateButton(view: android.view.View) {
        view.animate().scaleY(1.2f).scaleX(1.2f).setDuration(150).withEndAction {
            view.animate().scaleX(1f).scaleY(1f).setDuration(150).start()
        }.start()
    }

    private fun validateAndSaveChild() {
        if (binding.name.text.toString().isEmpty()|| imageUri == null|| binding.difficultyEt.text.toString().isEmpty()) {
            if (imageUri == null) {
                Toast.makeText(this, "Please select a profile picture", Toast.LENGTH_SHORT).show()
            }
            if (binding.name.text.toString().isEmpty()){
            binding.name.error = "Please enter a name"
            Toast.makeText(this, "Please enter a name", Toast.LENGTH_SHORT).show()
            }
            if (binding.difficultyEt.text.toString().isEmpty()){
                binding.difficultyEt.error = "Please enter a difficulty"
                Toast.makeText(this, "Please enter a difficulty", Toast.LENGTH_SHORT).show()
            }
        }
        else {
            name = binding.name.text.toString()
            difficulty = binding.difficultyEt.text.toString()
            viewModel.addChild(
                onStart = {onStarting()},
                name,
                age,
                gender,
                imageUri.toString(),
                pref.getProfileDetails().name,
                difficulty,
                pref,
                 this,
                 db,
                onEnd = { afterAddOrEdit() }
            )
            //finish()
        }
    }
    private fun validateAndUpdateChild() {
        if (binding.name.text.toString().isEmpty()|| imageUri == null|| binding.difficultyEt.text.toString().isEmpty()) {
            if (imageUri == null) {
                Toast.makeText(this, "Please select a profile picture", Toast.LENGTH_SHORT).show()
            }
            if (binding.name.text.toString().isEmpty()){
                binding.name.error = "Please enter a name"
                Toast.makeText(this, "Please enter a name", Toast.LENGTH_SHORT).show()
            }
            if (binding.difficultyEt.text.toString().isEmpty()){
                binding.difficultyEt.error = "Please enter a difficulty"
                Toast.makeText(this, "Please enter a difficulty", Toast.LENGTH_SHORT).show()
            }
        }
        else {
            name = binding.name.text.toString()
            difficulty = binding.difficultyEt.text.toString()
            updateChild()
             }
    }
    private fun updateChild() {
        viewModel.updateChild(
            { onStarting() },
            childId,
            name,
            age,
            imageUri.toString(),
            gender,
            difficulty,
            db,
            this,
            pref,
            { afterAddOrEdit() }
        )
    }
    @OptIn(DelicateCoroutinesApi::class)
    private fun getTheChildToView(childId: Int){
        GlobalScope.launch(Dispatchers.IO) {
            child = db.getChildById(childId)
            withContext(Dispatchers.Main){
                if (child != null) {
                    ////////SET_DATA////////////////
                    name = child!!.name
                    imageUri = Uri.parse(child!!.imageUri)
                    age = child!!.age
                    //disease = ChildDataFormatter.getTheDifficultyAndDisease(child!!.name).second
                    //difficulty = ChildDataFormatter.getTheDifficultyAndDisease(child!!.name).first
                    readingRate = child!!.readingRate
                    writingRate = child!!.writingRate
                    readingDays = child!!.readingDays
                    writingDays = child!!.writingDays
                    latestReadingDay = child!!.latestReadingDay
                    latestWritingDay = child!!.latestWritingDay
                    dateOfCreation = child!!.date
                    ///////////SET_VIEW////////////////
                    binding.report.visibility = android.view.View.VISIBLE
                    binding.doneBtn.text="Update"
                    binding.name.setText(child!!.name)
                    readingRate = child!!.readingRate
                    writingRate = child!!.writingRate
                    binding.profileIV.setImageURI(Uri.parse(child!!.imageUri))
                    binding.agePicker.value = child!!.age
                    if (child!!.gender == 0) {
                        binding.femaleRB.isChecked = true
                    } else {
                        binding.maleRB.isChecked = true }
                    binding.difficultyEt.setText(child!!.difficulty)
                }
                }

        }
    }


    private fun afterAddOrEdit(){
        binding.loadingView.visibility = android.view.View.GONE
        binding.doneBtn.isEnabled = true
        finish()

    }
    private fun onStarting(){
        Toast.makeText(this, "Wait ...", Toast.LENGTH_SHORT).show()
        binding.loadingView.visibility = android.view.View.VISIBLE
        binding.doneBtn.isEnabled = false
    }






}
