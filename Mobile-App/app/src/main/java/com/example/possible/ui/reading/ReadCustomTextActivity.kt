package com.example.possible.ui.reading

import DialogBuilder
import android.Manifest
import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.view.View
import android.view.View.GONE
import android.view.View.VISIBLE
import android.view.inputmethod.InputMethodManager
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.widget.doOnTextChanged
import com.example.possible.R
import com.example.possible.databinding.ActivityReadCustomTextBinding
import com.example.possible.util.helper.InterNetHelper
import java.util.Locale

class ReadCustomTextActivity : AppCompatActivity() {
    private lateinit var binding: ActivityReadCustomTextBinding
    private lateinit var speechRecognizer: SpeechRecognizer
    private lateinit var pulseAnimator: ObjectAnimator
    private var actualText = ""
    private var speechText = ""
    private var isRecording = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityReadCustomTextBinding.inflate(layoutInflater)
        setContentView(binding.root)
        if(!InterNetHelper.isInternetAvailable(this)){
            DialogBuilder.showInternetConnectionDialog(this) { this.finish() }
        }
        checkPermission()
        setupSpeechRecognizer()
        setupUI()
    }

    private fun setupUI() {
        binding.inputField.doOnTextChanged { text, _, _, _ ->
            binding.goBtn.setBackgroundResource(if (text.isNullOrEmpty()) R.drawable.is_not_recording else R.drawable.is_recording_bg)

        }

        binding.goBtn.setOnClickListener { handleGoButtonClick() }
        binding.recordBtn.setOnClickListener { toggleRecording() }
        binding.backArrowIV.setOnClickListener { finish() }
    }

    private fun checkPermission() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), 1)
        }
    }

    private fun setupSpeechRecognizer() {
        if (!SpeechRecognizer.isRecognitionAvailable(this)) {
            Toast.makeText(this, "Speech recognition not supported", Toast.LENGTH_LONG).show()
            return
        }

        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(this)
        speechRecognizer.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {
                showToast("Listening...")
            }

            override fun onBeginningOfSpeech() {
                animateRecording(true)
                showToast("Listening...")
            }

            override fun onEndOfSpeech() {
                animateRecording(false)
                isRecording = false
                //goToResult()
                //if (isRecording) speechRecognizer.startListening(getSpeechIntent())
            }

            override fun onError(error: Int) {
                showToast("Try again")
                if (isRecording && error != SpeechRecognizer.ERROR_CLIENT && error != SpeechRecognizer.ERROR_RECOGNIZER_BUSY) {
                    speechRecognizer.startListening(getSpeechIntent())
                }
            }

            override fun onResults(results: Bundle?) {
                results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)?.firstOrNull()?.let {
                    speechText = it
                    goToResult()
                }
            }

            override fun onPartialResults(partialResults: Bundle?) {
                partialResults?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)?.firstOrNull()?.let {
                    showToast(it)
                }
            }

            override fun onEvent(eventType: Int, params: Bundle?) {}
            override fun onRmsChanged(rmsdB: Float) {}
            override fun onBufferReceived(buffer: ByteArray?) {}
        })
    }

    private fun getSpeechIntent(): Intent {
        return Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault())
            putExtra(RecognizerIntent.EXTRA_PROMPT, "Speak something")
        }
    }

    private fun handleGoButtonClick() {
        if (binding.inputField.text.isNullOrEmpty()) return

        binding.readingText.text = binding.inputField.text
        binding.inputField.setText("")
        hideKeyboard()
        toggleInputVisibility(false)
    }

    private fun toggleRecording() {
        isRecording = !isRecording
        if (isRecording) {
            speechRecognizer.startListening(getSpeechIntent())
            setupPulseAnimation()
            pulseAnimator.start()
        } else {
            speechRecognizer.stopListening()
            animateRecording(false)
            goToResult()
        }
    }

    private fun goToResult() {
        val intent = Intent(this, ReadingResult::class.java).apply {
            putExtra("actualText", binding.readingText.text.toString())
            putExtra("speechText", speechText)
        }
        startActivity(intent)
    }

    private fun animateRecording(isRecording: Boolean) {
        binding.recordBtn.animate().scaleX(if (isRecording) 1.2f else 1f).scaleY(if (isRecording) 1.2f else 1f).setDuration(100).withEndAction {
            binding.recordBtn.setBackgroundResource(if (isRecording) R.drawable.is_recording_bg else R.drawable.is_not_recording)
        }.start()
        pulseAnimator.cancel()
    }

    private fun setupPulseAnimation() {
        pulseAnimator = ObjectAnimator.ofPropertyValuesHolder(
            binding.recordSignals,
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.2f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.2f)
        ).apply {
            duration = 500
            repeatMode = ObjectAnimator.REVERSE
            repeatCount = ObjectAnimator.INFINITE
        }
    }

    private fun hideKeyboard() {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        imm.hideSoftInputFromWindow(binding.inputField.windowToken, 0)
    }

    private fun toggleInputVisibility(showInput: Boolean) {
        binding.goBtn.visibility = if (showInput) VISIBLE else GONE
        binding.inputField.visibility = if (showInput) VISIBLE else GONE
        binding.recordBtn.visibility = if (showInput) GONE else VISIBLE
        binding.hintCard.visibility = if (showInput) GONE else VISIBLE
        binding.recordSignals.visibility = if (showInput) GONE else VISIBLE
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        speechRecognizer.destroy()
    }
}
