package com.example.possible.ui.reading

import android.Manifest
import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.view.View
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.example.possible.R
import com.example.possible.databinding.ActivityReadTextBinding
import com.example.possible.util.adapter.TextsAdapter
import com.example.possible.util.helper.InterNetHelper
import com.example.possible.util.listener.TextListener
import java.util.Locale

class ReadTextActivity : AppCompatActivity(), TextListener {

    private lateinit var binding: ActivityReadTextBinding
    private lateinit var pulseAnimator: ObjectAnimator
    private lateinit var speechRecognizer: SpeechRecognizer
    private lateinit var adapter: TextsAdapter

    private var actualText = ""
    private var speechText = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityReadTextBinding.inflate(layoutInflater)
        enableEdgeToEdge()
        setContentView(binding.root)

        setupUI()
        checkAudioPermission()
        setupSpeechRecognizer()
    }

    private fun setupUI() {
        setupRecyclerView()
        setupClickListeners()
        if(!InterNetHelper.isInternetAvailable(this)){
            DialogBuilder.showInternetConnectionDialog(this) { this.finish() }
        }
    }

    private fun setupRecyclerView() {
        val texts = arrayListOf(
            "The cat is black",
            "I like my dog",
            "The sun is hot",
            "I see a bird",
            "She has a red ball",
            "We play in the park",
            "The sky is blue",
            "He has a big hat",
            "The fish swims fast",
            "I love my mom",
            "The dog barks loud",
            "We eat apples",
            "The car is red",
            "I can jump high",
            "The tree is tall",
            "Birds can fly",
            "The cake is sweet",
            "I see the moon",
            "The boy runs fast",
            "The stars are bright",
            "The rain is wet",
            "My shoes are new",
            "I like ice cream",
            "The frog is green",
            "The sun shines bright",
            "My bike is blue",
            "We swim in the pool",
            "The fox is smart",
            "The duck swims fast",
            "I see a rainbow",
            "The cow says moo",
            "I have a toy car",
            "The bird sings sweet",
            "I like to read",
            "The dog has fur",
            "The cat sleeps well",
            "The sheep is white",
            "The mouse is small",
            "The cake is big",
            "The leaf is green",
            "The fox runs fast",
            "I like to draw",
            "The kite flies high",
            "The pig is pink",
            "The snow is cold",
            "The bear is big",
            "I see a tree",
            "The horse is brown",
            "The fire is hot",
            "The wind is strong"
        )

        adapter = TextsAdapter(texts, this)
        binding.recyclerView.adapter = adapter
    }

    private fun checkAudioPermission() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), 1)
        }
    }

    private fun setupSpeechRecognizer() {
        if (!SpeechRecognizer.isRecognitionAvailable(this)) {
            showToast("Speech recognition not supported")
            return
        }

        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(this)
        speechRecognizer.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) = showListeningUI()
            override fun onEndOfSpeech() = stopListeningUI()
            override fun onResults(results: Bundle?) {
                speechText = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)?.getOrNull(0) ?: ""
                navigateToResult()
            }
            override fun onError(error: Int) {}
            override fun onPartialResults(partialResults: Bundle?) {}
            override fun onRmsChanged(rmsdB: Float) {}
            override fun onBufferReceived(buffer: ByteArray?) {}
            override fun onBeginningOfSpeech() {}
            override fun onEvent(eventType: Int, params: Bundle?) {}
        })
    }

    private fun getSpeechIntent() = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
        putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
        putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault())
        putExtra(RecognizerIntent.EXTRA_PROMPT, "Speak something")
    }

    private fun setupClickListeners() {
        binding.recordBtn.setOnClickListener {
            speechRecognizer.startListening(getSpeechIntent())
            startPulseAnimation()
        }
        binding.backArrowIV.setOnClickListener { finish() }
    }

    private fun startPulseAnimation() {
        pulseAnimator = ObjectAnimator.ofPropertyValuesHolder(
            binding.recordSignals,
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.2f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.2f)
        ).apply {
            duration = 500
            repeatMode = ObjectAnimator.REVERSE
            repeatCount = ObjectAnimator.INFINITE
            start()
        }
    }

    private fun showListeningUI() {
        binding.hint.visibility = View.GONE
        binding.recordSignals.visibility = View.VISIBLE
        pulseAnimator.start()
    }

    private fun stopListeningUI() {
        binding.recordBtn.setBackgroundResource(R.drawable.is_not_recording)
        pulseAnimator.cancel()
    }

    private fun navigateToResult() {
        val intent = Intent(this, ReadingResult::class.java).apply {
            putExtra("actualText", actualText)
            putExtra("speechText", speechText)
        }
        startActivity(intent)
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
       try{
        super.onDestroy()
        speechRecognizer.destroy()
        pulseAnimator.cancel()} catch (_: Exception){
           Toast.makeText(this, "ok", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onClick(text: String) {
        actualText = text
        binding.actualText.text = text
        binding.theMainView.visibility = View.VISIBLE
        binding.dummyView.visibility = View.GONE
    }
}
