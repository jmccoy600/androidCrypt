package com.androidcrypt.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.androidcrypt.crypto.VolumeCreator
import com.androidcrypt.crypto.VolumeMountManager
import com.androidcrypt.crypto.MountedVolumeInfo
import com.androidcrypt.crypto.FAT32Reader
import com.androidcrypt.crypto.FileEntry
import com.androidcrypt.ui.theme.AndroidCryptTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.ByteArrayInputStream
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (!isGranted) {
            // Handle permission denial
        }
    }
    
    private val requestNotificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        // Notification permission granted or denied
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Request storage permission if needed
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11+: Scoped storage, no permission needed for app-specific directory
        } else {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissionLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        }
        
        // Request notification permission for Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        
        setContent {
            AndroidCryptTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen()
                }
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Unmount all volumes when app is closed
        VolumeMountManager.unmountAll()
        Log.d("MainActivity", "All volumes unmounted on app close")
    }
}

@Composable
fun MainScreen() {
    var selectedTab by remember { mutableStateOf(0) }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
    ) {
        ScrollableTabRow(selectedTabIndex = selectedTab) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text("Open") }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { Text("Create") }
            )
            Tab(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2 },
                text = { Text("File Manager") }
            )
            Tab(
                selected = selectedTab == 3,
                onClick = { selectedTab = 3 },
                text = { Text("Util") }
            )
            Tab(
                selected = selectedTab == 4,
                onClick = { selectedTab = 4 },
                text = { Text("How to Use") }
            )
        }
        
        when (selectedTab) {
            0 -> OpenContainerScreen(onNavigateToTab = { selectedTab = it })
            1 -> CreateContainerScreen()
            2 -> FileManagerScreen()
            3 -> UtilScreen()
            4 -> HowToUseScreen()
        }
    }
}

@Composable
fun OpenContainerScreen(onNavigateToTab: (Int) -> Unit = {}) {
    var containerUri by remember { mutableStateOf<Uri?>(null) }
    var containerDisplayName by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var statusMessage by remember { mutableStateOf("") }
    var statusColor by remember { mutableStateOf(Color.Gray) }
    var isMounted by remember { mutableStateOf(false) }
    var volumeInfo by remember { mutableStateOf<MountedVolumeInfo?>(null) }
    var isLoading by remember { mutableStateOf(false) }
    var keyfileUris by remember { mutableStateOf<List<Uri>>(emptyList()) }
    var keyfileNames by remember { mutableStateOf<List<String>>(emptyList()) }
    var useKeyfiles by remember { mutableStateOf(false) }
    
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    // File picker launcher for container
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            // Take persistable permission so we can access the file later
            context.contentResolver.takePersistableUriPermission(
                it,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
            containerUri = it
            // Get display name for the file
            containerDisplayName = context.contentResolver.query(
                it,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null, null, null
            )?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: it.lastPathSegment ?: it.toString()
        }
    }
    
    // File picker launcher for keyfiles (can select multiple)
    val keyfilePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> ->
        val newNames = mutableListOf<String>()
        uris.forEach { uri ->
            // Take persistable permission for each keyfile
            try {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (e: Exception) {
                // Permission might not be persistable, continue anyway
            }
            // Get display name
            val name = context.contentResolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null, null, null
            )?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: uri.lastPathSegment ?: "keyfile"
            newNames.add(name)
        }
        keyfileUris = keyfileUris + uris
        keyfileNames = keyfileNames + newNames
    }
    
    // Check if already mounted
    LaunchedEffect(containerUri) {
        val uriString = containerUri?.toString() ?: ""
        isMounted = VolumeMountManager.isMounted(uriString)
        if (isMounted) {
            volumeInfo = VolumeMountManager.getVolumeReader(uriString)?.volumeInfo
        }
    }
    
    // Also refresh mount status periodically to catch external changes
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(1000)
            val uriString = containerUri?.toString() ?: ""
            val currentlyMounted = VolumeMountManager.isMounted(uriString)
            if (currentlyMounted != isMounted) {
                isMounted = currentlyMounted
                if (isMounted) {
                    volumeInfo = VolumeMountManager.getVolumeReader(uriString)?.volumeInfo
                }
            }
        }
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
            .padding(top = 16.dp, bottom = 80.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Mount VeraCrypt Container",
            style = MaterialTheme.typography.headlineMedium
        )
        
        // Display selected file
        OutlinedTextField(
            value = containerDisplayName,
            onValueChange = { },
            label = { Text("Container File") },
            modifier = Modifier.fillMaxWidth(),
            enabled = false,
            placeholder = { Text("Select a container file...") }
        )
        
        OutlinedButton(
            onClick = { 
                filePickerLauncher.launch(arrayOf("*/*"))
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isMounted
        ) {
            Text("Browse...")
        }
        
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isMounted,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                autoCorrect = false
            )
        )
        
        OutlinedTextField(
            value = pim,
            onValueChange = { pim = it },
            label = { Text("PIM (optional)") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isMounted,
            placeholder = { Text("0 for default") }
        )
        
        // Keyfiles section
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(
                checked = useKeyfiles,
                onCheckedChange = { useKeyfiles = it },
                enabled = !isMounted
            )
            Text("Use keyfiles")
        }
        
        if (useKeyfiles) {
            OutlinedButton(
                onClick = { 
                    keyfilePickerLauncher.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isMounted
            ) {
                Text("Add Keyfiles...")
            }
            
            if (keyfileUris.isNotEmpty()) {
                Text(
                    text = "${keyfileUris.size} keyfile(s) selected",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color.Gray
                )
                
                // List keyfiles
                keyfileUris.forEachIndexed { index, uri ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = keyfileNames.getOrElse(index) { uri.lastPathSegment ?: "keyfile" },
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodySmall
                        )
                        TextButton(
                            onClick = { 
                                keyfileUris = keyfileUris.filterIndexed { i, _ -> i != index }
                                keyfileNames = keyfileNames.filterIndexed { i, _ -> i != index }
                            },
                            enabled = !isMounted
                        ) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
        
        if (!isMounted) {
            Button(
                onClick = {
                    if (containerUri == null) {
                        statusMessage = "Please select a container file"
                        statusColor = Color.Red
                        return@Button
                    }
                    if (password.isEmpty() && keyfileUris.isEmpty()) {
                        statusMessage = "Please enter password or select keyfiles"
                        statusColor = Color.Red
                        return@Button
                    }
                    
                    statusMessage = "Mounting container..."
                    statusColor = Color.Blue
                    isLoading = true
                    
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            val pimValue = pim.toIntOrNull() ?: 0
                            VolumeMountManager.mountVolumeFromUri(
                                context = context,
                                uri = containerUri!!,
                                password = password,
                                pim = pimValue,
                                keyfileUris = if (useKeyfiles) keyfileUris else emptyList()
                            )
                        }
                        
                        isLoading = false
                        result.fold(
                            onSuccess = { info ->
                                volumeInfo = info
                                isMounted = true
                                statusMessage = "✓ Successfully mounted!\n" +
                                    "Total size: ${info.totalSize / (1024 * 1024)} MB\n" +
                                    "Data area: ${info.getDataAreaSizeMB()} MB\n" +
                                    "Sector size: ${info.sectorSize} bytes\n\n" +
                                    "📁 Volume is now accessible to other apps through:\n" +
                                    "Files app → ☰ Menu → VeraCrypt Volume"
                                statusColor = Color(0xFF4CAF50)
                                
                                // Navigate to file manager tab
                                onNavigateToTab(2)
                            },
                            onFailure = { e ->
                                statusMessage = "Failed to mount container:\n${e.message}"
                                statusColor = Color.Red
                            }
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isLoading
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text("Mount Container")
            }
        } else {
            // Mounted state - show unmount button
            Button(
                onClick = {
                    scope.launch {
                        val uriString = containerUri?.toString() ?: ""
                        val result = withContext(Dispatchers.IO) {
                            VolumeMountManager.unmountVolume(uriString)
                        }
                        
                        result.fold(
                            onSuccess = {
                                isMounted = false
                                volumeInfo = null
                                statusMessage = "Container unmounted successfully"
                                statusColor = Color.Gray
                            },
                            onFailure = { e ->
                                statusMessage = "Failed to unmount:\n${e.message}"
                                statusColor = Color.Red
                            }
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text("Unmount")
            }
        }
        
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = when (statusColor) {
                        Color.Red -> Color(0xFFFFEBEE)
                        Color(0xFF4CAF50) -> Color(0xFFE8F5E9)
                        else -> MaterialTheme.colorScheme.secondaryContainer
                    }
                )
            ) {
                Text(
                    text = statusMessage,
                    modifier = Modifier.padding(16.dp),
                    color = statusColor
                )
            }
        }
        
        Text(
            text = "Note: This app provides basic VeraCrypt container support. " +
                    "Only AES encryption is currently supported.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        // Link to How to Use tab
        TextButton(
            onClick = { onNavigateToTab(4) },
            modifier = Modifier.align(Alignment.CenterHorizontally)
        ) {
            Icon(
                imageVector = Icons.Default.Info,
                contentDescription = "How to use",
                modifier = Modifier
                    .size(18.dp)
                    .padding(end = 4.dp)
            )
            Text(
                text = "How to Use AndroidCrypt",
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
fun CreateContainerScreen() {
    var containerPath by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var containerSize by remember { mutableStateOf("10") }
    var pim by remember { mutableStateOf("") }
    var statusMessage by remember { mutableStateOf("") }
    var isCreating by remember { mutableStateOf(false) }
    var keyfileUris by remember { mutableStateOf<List<Uri>>(emptyList()) }
    var keyfileNames by remember { mutableStateOf<List<String>>(emptyList()) }
    var useKeyfiles by remember { mutableStateOf(false) }
    
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    // File picker launcher for keyfiles (can select multiple)
    val keyfilePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> ->
        val newNames = mutableListOf<String>()
        uris.forEach { uri ->
            // Take persistable permission for each keyfile
            try {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (e: Exception) {
                // Permission might not be persistable, continue anyway
            }
            // Get display name
            val name = context.contentResolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null, null, null
            )?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: uri.lastPathSegment ?: "keyfile"
            newNames.add(name)
        }
        keyfileUris = keyfileUris + uris
        keyfileNames = keyfileNames + newNames
    }
    
    // Suggest default path on first load
    LaunchedEffect(Unit) {
        if (containerPath.isEmpty()) {
            containerPath = "/storage/emulated/0/Download/mycontainer.hc"
        }
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
            .padding(top = 16.dp, bottom = 80.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Create New Container",
            style = MaterialTheme.typography.headlineMedium
        )
        
        OutlinedTextField(
            value = containerPath,
            onValueChange = { containerPath = it },
            label = { Text("Container File Path") },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("/storage/emulated/0/mycontainer.hc") }
        )
        
        OutlinedTextField(
            value = containerSize,
            onValueChange = { 
                // Only allow digits
                if (it.isEmpty() || it.all { char -> char.isDigit() }) {
                    containerSize = it
                }
            },
            label = { Text("Container Size (MB)") },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("10") }
        )
        
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                autoCorrect = false
            ),
            supportingText = { 
                Text("Can be empty if using keyfiles") 
            }
        )
        
        OutlinedTextField(
            value = confirmPassword,
            onValueChange = { confirmPassword = it },
            label = { Text("Confirm Password") },
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                autoCorrect = false
            )
        )
        
        OutlinedTextField(
            value = pim,
            onValueChange = { pim = it },
            label = { Text("PIM (optional)") },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("0 for default") }
        )
        
        // Keyfiles section
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(
                checked = useKeyfiles,
                onCheckedChange = { useKeyfiles = it },
                enabled = !isCreating
            )
            Text("Use keyfiles")
        }
        
        if (useKeyfiles) {
            OutlinedButton(
                onClick = { 
                    keyfilePickerLauncher.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isCreating
            ) {
                Text("Add Keyfiles...")
            }
            
            if (keyfileUris.isNotEmpty()) {
                Text(
                    text = "${keyfileUris.size} keyfile(s) selected",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color.Gray
                )
                
                // List keyfiles
                keyfileUris.forEachIndexed { index, uri ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = keyfileNames.getOrElse(index) { uri.lastPathSegment ?: "keyfile" },
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodySmall
                        )
                        TextButton(
                            onClick = { 
                                keyfileUris = keyfileUris.filterIndexed { i, _ -> i != index }
                                keyfileNames = keyfileNames.filterIndexed { i, _ -> i != index }
                            },
                            enabled = !isCreating
                        ) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
        
        Button(
            onClick = {
                if (password != confirmPassword) {
                    statusMessage = "Error: Passwords do not match!"
                    return@Button
                }
                if (password.isEmpty() && keyfileUris.isEmpty()) {
                    statusMessage = "Error: Password or keyfiles required!"
                    return@Button
                }
                
                val sizeMB = containerSize.toLongOrNull()
                if (sizeMB == null || sizeMB < 1) {
                    statusMessage = "Error: Invalid container size!"
                    return@Button
                }
                
                isCreating = true
                statusMessage = "Creating container... Please wait."
                
                scope.launch {
                    try {
                        val result = withContext(Dispatchers.IO) {
                            val pimValue = pim.toIntOrNull() ?: 0
                            VolumeCreator.createContainer(
                                containerPath = containerPath,
                                password = password,
                                sizeInMB = sizeMB,
                                pim = pimValue,
                                keyfileUris = if (useKeyfiles) keyfileUris else emptyList(),
                                context = context
                            )
                        }
                        
                        statusMessage = result.getOrElse { e ->
                            "Error: ${e.message}"
                        }
                    } catch (e: Exception) {
                        statusMessage = "Error: ${e.message}"
                    } finally {
                        isCreating = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = containerPath.isNotEmpty() && (password.isNotEmpty() || keyfileUris.isNotEmpty()) && !isCreating
        ) {
            if (isCreating) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(if (isCreating) "Creating..." else "Create Container")
        }
        
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (statusMessage.contains("success", ignoreCase = true))
                        MaterialTheme.colorScheme.primaryContainer
                    else if (statusMessage.contains("error", ignoreCase = true) || 
                             statusMessage.contains("!"))
                        MaterialTheme.colorScheme.errorContainer
                    else
                        MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Text(
                    text = statusMessage,
                    modifier = Modifier.padding(16.dp)
                )
            }
        }
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Encryption Settings",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Text("Algorithm: AES", style = MaterialTheme.typography.bodyMedium)
                Text("Mode: XTS", style = MaterialTheme.typography.bodyMedium)
                Text("Hash: SHA-512", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
fun UtilScreen() {
    var statusMessage by remember { mutableStateOf("") }
    var statusColor by remember { mutableStateOf(Color.Gray) }
    val scope = rememberCoroutineScope()
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Utilities",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Volume Management",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "Use this button to unmount all currently mounted volumes. This is useful for clearing stale volumes or ensuring all volumes are properly closed.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            withContext(Dispatchers.IO) {
                                VolumeMountManager.unmountAll()
                            }
                            statusMessage = "All volumes unmounted successfully"
                            statusColor = Color(0xFF4CAF50)
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Unmount all",
                        modifier = Modifier.padding(end = 8.dp)
                    )
                    Text("Unmount All Volumes")
                }
            }
        }
        
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                )
            ) {
                Text(
                    text = statusMessage,
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = statusColor
                )
            }
        }
    }
}

@Composable
fun HowToUseScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
            .padding(top = 16.dp, bottom = 80.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "How to Use AndroidCrypt",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        
        // Creating a Container Section
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "📦 The first step is creating an encrypted file container",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "1. Go to the 'Create' tab",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "2. Tap 'Choose Location' and select where to save your container file",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "3. Enter a container size (in MB)",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "4. Enter a strong password and confirm it",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "5. (Optional) Add keyfiles for additional security",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "6. Tap 'Create Container' and wait for completion",
                    style = MaterialTheme.typography.bodyLarge
                )
            }
        }
        
        // Mounting a Container Section
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "🔓 Opening (Mounting) a Container",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "1. Go to the 'Open' tab",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "2. Tap 'Choose Container' and select your encrypted file",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "3. Enter your password",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "4. If you used keyfiles, add them",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "5. Tap 'Mount Container'",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "6. Access your files through your system file manager or through the built in file manager tab",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "7. When done, tap 'Unmount' to close the container",
                    style = MaterialTheme.typography.bodyLarge
                )
            }
        }
        
        // File Size Recommendations
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.tertiaryContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "💡 Container Size Recommendations",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "Small (10-100 MB)",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = "Good for: Text documents, passwords, small files",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "Medium (100-500 MB)",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = "Good for: Photos, PDFs, office documents",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "Large (500-2000 MB)",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = "Good for: Photo albums, music collections",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "Very Large (2000+ MB)",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = "Good for: Video files, large archives",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
        
        // Important Notes
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "⚠️ Important Notes",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                Text(
                    text = "• Never forget your password - there is NO password recovery",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "• Keep keyfiles safe - you need them to access your data",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "• Always unmount containers when finished",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                Text(
                    text = "• Compatible with VeraCrypt desktop application AES encrypted file containers",
                    style = MaterialTheme.typography.bodyLarge
                )
            }
        }
    }
}

@Composable
fun FileManagerScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    // Mounted volume state
    var mountedVolumes by remember { mutableStateOf(VolumeMountManager.getMountedVolumes()) }
    var selectedVolume by remember { mutableStateOf<String?>(null) }
    var volumeInfo by remember { mutableStateOf<MountedVolumeInfo?>(null) }
    var fileCount by remember { mutableStateOf(0) }
    var usedSpace by remember { mutableStateOf(0L) }
    var freeSpace by remember { mutableStateOf(0L) }
    var totalSpace by remember { mutableStateOf(0L) }
    
    // UI state
    var statusMessage by remember { mutableStateOf("") }
    var statusColor by remember { mutableStateOf(Color.Gray) }
    var isLoading by remember { mutableStateOf(false) }
    var copyProgress by remember { mutableStateOf("") }
    var isCopying by remember { mutableStateOf(false) }
    
    // Export state - for selecting files/folders from volume
    var showFilePickerDialog by remember { mutableStateOf(false) }
    var showFolderPickerDialog by remember { mutableStateOf(false) }
    var volumeFiles by remember { mutableStateOf<List<FileEntry>>(emptyList()) }
    var currentPath by remember { mutableStateOf("/") }
    var selectedExportFile by remember { mutableStateOf<FileEntry?>(null) }
    var selectedExportFolder by remember { mutableStateOf<FileEntry?>(null) }
    
    // Destination picker for exporting a file from volume to device
    val exportFileDestinationLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { destUri ->
        if (destUri != null && selectedVolume != null && selectedExportFile != null) {
            val fileToExport = selectedExportFile!!
            scope.launch {
                isCopying = true
                copyProgress = "Exporting: ${fileToExport.name}"
                statusMessage = ""
                
                try {
                    val volumeReader = VolumeMountManager.getVolumeReader(selectedVolume!!)
                    if (volumeReader != null) {
                        val reader = FAT32Reader(volumeReader)
                        reader.initialize()
                        
                        withContext(Dispatchers.IO) {
                            exportFileFromVolume(context, reader, fileToExport, destUri)
                        }
                        
                        statusMessage = "✓ File exported successfully!"
                        statusColor = Color(0xFF4CAF50)
                    }
                } catch (e: Exception) {
                    Log.e("FileManager", "Failed to export file", e)
                    statusMessage = "✗ Export failed: ${e.message}"
                    statusColor = Color.Red
                } finally {
                    isCopying = false
                    copyProgress = ""
                    selectedExportFile = null
                }
            }
        }
    }
    
    // Destination picker for exporting a folder from volume to device
    val exportFolderDestinationLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { destUri ->
        if (destUri != null && selectedVolume != null && selectedExportFolder != null) {
            val folderToExport = selectedExportFolder!!
            scope.launch {
                isCopying = true
                copyProgress = "Counting files..."
                statusMessage = ""
                
                try {
                    val volumeReader = VolumeMountManager.getVolumeReader(selectedVolume!!)
                    if (volumeReader != null) {
                        val reader = FAT32Reader(volumeReader)
                        reader.initialize()
                        
                        withContext(Dispatchers.IO) {
                            // Count files in the folder first
                            val totalFiles = countFilesInVolumeFolder(reader, folderToExport.path)
                            val counter = CopyCounter(totalFiles)
                            
                            exportFolderFromVolume(context, reader, folderToExport, destUri, counter) { progress ->
                                copyProgress = progress
                            }
                        }
                        
                        statusMessage = "✓ Folder exported successfully!"
                        statusColor = Color(0xFF4CAF50)
                    }
                } catch (e: Exception) {
                    Log.e("FileManager", "Failed to export folder", e)
                    statusMessage = "✗ Export failed: ${e.message}"
                    statusColor = Color.Red
                } finally {
                    isCopying = false
                    copyProgress = ""
                    selectedExportFolder = null
                }
            }
        }
    }
    
    // File picker launcher for copying single files from device
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null && selectedVolume != null) {
            // Take persistent permission for the file
            try {
                val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                context.contentResolver.takePersistableUriPermission(uri, takeFlags)
            } catch (e: Exception) {
                // Some URIs don't support persistent permissions
            }
            
            val intent = Intent(context, CopyService::class.java).apply {
                action = CopyService.ACTION_COPY_FILE_TO_VOLUME
                putExtra(CopyService.EXTRA_SOURCE_URI, uri)
                putExtra(CopyService.EXTRA_VOLUME_PATH, selectedVolume)
            }
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            
            isCopying = true
            copyProgress = "Starting copy service..."
            statusMessage = ""
        }
    }
    
    // Folder picker launcher for copying folders from device
    val folderPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null && selectedVolume != null) {
            // Take persistent permission for the folder
            val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            context.contentResolver.takePersistableUriPermission(uri, takeFlags)
            
            // Get folder name and start the CopyService
            val folderName = getFolderNameFromUri(context, uri)
            
            val intent = Intent(context, CopyService::class.java).apply {
                action = CopyService.ACTION_COPY_FOLDER_TO_VOLUME
                putExtra(CopyService.EXTRA_SOURCE_URI, uri)
                putExtra(CopyService.EXTRA_VOLUME_PATH, selectedVolume)
                putExtra(CopyService.EXTRA_FOLDER_NAME, folderName)
            }
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            
            isCopying = true
            copyProgress = "Starting copy service..."
            statusMessage = ""
        }
    }
    
    // Observe CopyService state
    val copyState by CopyService.copyState.collectAsStateWithLifecycle()
    val serviceProgress by CopyService.progress.collectAsStateWithLifecycle()
    val isServiceRunning by CopyService.isRunning.collectAsStateWithLifecycle()
    
    // React to service state changes
    LaunchedEffect(copyState) {
        when (val state = copyState) {
            is CopyService.CopyState.Copying -> {
                isCopying = true
                copyProgress = state.progress
            }
            is CopyService.CopyState.Completed -> {
                isCopying = false
                copyProgress = ""
                statusMessage = "✓ ${state.message}"
                statusColor = Color(0xFF4CAF50)
                
                // Refresh file count and space
                if (selectedVolume != null) {
                    scope.launch(Dispatchers.IO) {
                        val volumeReader = VolumeMountManager.getVolumeReader(selectedVolume!!)
                        if (volumeReader != null) {
                            val reader = FAT32Reader(volumeReader)
                            reader.initialize()
                            val rootFiles = reader.listDirectory("/").getOrDefault(emptyList())
                            fileCount = countAllFiles(rootFiles, reader)
                            usedSpace = calculateUsedSpace(rootFiles, reader)
                            // Calculate accurate free/total space from cluster counting
                            totalSpace = reader.getTotalSpaceBytes()
                            val freeClusters = reader.countFreeClusters()
                            val clusterSize = reader.getClusterSize()
                            freeSpace = freeClusters.toLong() * clusterSize
                        }
                    }
                }
            }
            is CopyService.CopyState.Error -> {
                isCopying = false
                copyProgress = ""
                statusMessage = "✗ ${state.message}"
                statusColor = Color.Red
            }
            is CopyService.CopyState.Idle -> {
                // Service is idle
            }
        }
    }
    
    // Refresh mounted volumes
    LaunchedEffect(Unit) {
        mountedVolumes = VolumeMountManager.getMountedVolumes()
        if (mountedVolumes.isNotEmpty() && selectedVolume == null) {
            selectedVolume = mountedVolumes.first()
        }
    }
    
    // Get volume info when volume is selected
    LaunchedEffect(selectedVolume) {
        selectedVolume?.let { volumePath ->
            isLoading = true
            val volumeReader = VolumeMountManager.getVolumeReader(volumePath)
            volumeInfo = volumeReader?.volumeInfo
            
            // Count files and used space
            if (volumeReader != null) {
                withContext(Dispatchers.IO) {
                    try {
                        val reader = FAT32Reader(volumeReader)
                        reader.initialize()
                        val rootFiles = reader.listDirectory("/").getOrDefault(emptyList())
                        fileCount = countAllFiles(rootFiles, reader)
                        usedSpace = calculateUsedSpace(rootFiles, reader)
                        // Calculate accurate free/total space from cluster counting
                        totalSpace = reader.getTotalSpaceBytes()
                        val freeClusters = reader.countFreeClusters()
                        val clusterSize = reader.getClusterSize()
                        freeSpace = freeClusters.toLong() * clusterSize
                    } catch (e: Exception) {
                        Log.e("FileManager", "Failed to get volume stats", e)
                    }
                }
            }
            isLoading = false
        }
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "File Manager",
            style = MaterialTheme.typography.headlineMedium
        )
        
        // Status message
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = when (statusColor) {
                        Color.Red -> Color(0xFFFFEBEE)
                        Color(0xFF4CAF50) -> Color(0xFFE8F5E9)
                        else -> MaterialTheme.colorScheme.secondaryContainer
                    }
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = statusMessage,
                        modifier = Modifier.weight(1f),
                        color = statusColor
                    )
                    IconButton(
                        onClick = { statusMessage = "" },
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Dismiss",
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }
        
        if (mountedVolumes.isEmpty()) {
            // No volume mounted
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "No Volume Mounted",
                        style = MaterialTheme.typography.titleLarge
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Open and mount a VeraCrypt container first to access files.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            // Volume is mounted - show info and open button
            if (isLoading) {
                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                // Volume Info Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFE8F5E9)
                    )
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = Color(0xFF4CAF50),
                                    modifier = Modifier.size(24.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Volume Mounted",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = Color(0xFF4CAF50)
                                )
                            }
                            
                            OutlinedButton(
                                onClick = {
                                    scope.launch {
                                        selectedVolume?.let { volume ->
                                            withContext(Dispatchers.IO) {
                                                VolumeMountManager.unmountVolume(volume)
                                            }
                                            mountedVolumes = VolumeMountManager.getMountedVolumes()
                                            selectedVolume = null
                                            volumeInfo = null
                                            statusMessage = "Volume unmounted successfully"
                                            statusColor = Color.Gray
                                        }
                                    }
                                },
                                colors = ButtonDefaults.outlinedButtonColors(
                                    contentColor = MaterialTheme.colorScheme.error
                                ),
                                modifier = Modifier.height(36.dp)
                            ) {
                                Text(
                                    text = "Unmount",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        volumeInfo?.let { info ->
                            Text(
                                text = "Total Size: ${info.totalSize / (1024 * 1024)} MB",
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.Black
                            )
                            Text(
                                text = "Data Area: ${info.getDataAreaSizeMB()} MB",
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.Black
                            )
                            Text(
                                text = "Files: $fileCount",
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.Black
                            )
                            
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            // Storage usage progress bar
                            val usageProgress = if (totalSpace > 0) {
                                (usedSpace.toFloat() / totalSpace.toFloat()).coerceIn(0f, 1f)
                            } else 0f
                            
                            Text(
                                text = "Storage Usage",
                                style = MaterialTheme.typography.labelMedium,
                                color = Color.Black
                            )
                            
                            Spacer(modifier = Modifier.height(4.dp))
                            
                            LinearProgressIndicator(
                                progress = { usageProgress },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(8.dp)
                                    .clip(RoundedCornerShape(4.dp)),
                                color = when {
                                    usageProgress > 0.9f -> Color(0xFFF44336) // Red when nearly full
                                    usageProgress > 0.75f -> Color(0xFFFF9800) // Orange when getting full
                                    else -> Color(0xFF4CAF50) // Green otherwise
                                },
                                trackColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                            
                            Spacer(modifier = Modifier.height(4.dp))
                            
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Used: ${formatFileSize(usedSpace)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Black
                                )
                                Text(
                                    text = "Free: ${formatFileSize(freeSpace)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Black
                                )
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Open in Files App button
                Button(
                    onClick = {
                        try {
                            // Build URI for our DocumentsProvider root
                            val authority = "com.androidcrypt.documents"
                            val rootId = "veracrypt_${selectedVolume?.hashCode()}"
                            val documentId = "$rootId:/"
                            
                            // Create URI to open in document browser
                            val rootUri = DocumentsContract.buildRootUri(authority, rootId)
                            val documentUri = DocumentsContract.buildDocumentUri(authority, documentId)
                            
                            // Try ACTION_VIEW first (opens Files app directly to location)
                            val intent = Intent(Intent.ACTION_VIEW).apply {
                                setDataAndType(documentUri, DocumentsContract.Document.MIME_TYPE_DIR)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                            }
                            
                            // Check if there's an app that can handle this
                            if (intent.resolveActivity(context.packageManager) != null) {
                                context.startActivity(intent)
                            } else {
                                // Fallback: Open document picker (user can navigate to VeraCrypt Volume in sidebar)
                                val fallbackIntent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
                                    putExtra(DocumentsContract.EXTRA_INITIAL_URI, documentUri)
                                }
                                context.startActivity(fallbackIntent)
                                
                                statusMessage = "Look for 'VeraCrypt Volume' in the sidebar (☰ menu)"
                                statusColor = Color(0xFF2196F3)
                            }
                        } catch (e: Exception) {
                            Log.e("FileManager", "Failed to open Files app", e)
                            statusMessage = "Could not open Files app: ${e.message}"
                            statusColor = Color.Red
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        imageVector = Icons.Default.List,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Open in Files App")
                }
                
                // Copy folder from device button
                Button(
                    onClick = { folderPickerLauncher.launch(null) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isCopying,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF1565C0)
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Copy Folder from Device")
                }
                
                // Show copy progress
                if (isCopying) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFFE3F2FD)
                        )
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(24.dp),
                                    strokeWidth = 2.dp
                                )
                                Spacer(modifier = Modifier.width(12.dp))
                                Text(
                                    text = copyProgress,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = Color.Black,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            TextButton(
                                onClick = {
                                    // Cancel the copy service
                                    val intent = Intent(context, CopyService::class.java).apply {
                                        action = CopyService.ACTION_CANCEL
                                    }
                                    context.startService(intent)
                                },
                                colors = ButtonDefaults.textButtonColors(
                                    contentColor = Color.Red
                                )
                            ) {
                                Text("Cancel Copy")
                            }
                        }
                    }
                }
                
                // Copy single file from device to volume
                Button(
                    onClick = {
                        filePickerLauncher.launch(arrayOf("*/*"))
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isCopying,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF1565C0)
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Copy File from Device")
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Copy file from volume to device
                Button(
                    onClick = { showFilePickerDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isCopying,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF42A5F5)
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Copy File to Device")
                }
                
                // Copy folder from volume to device
                Button(
                    onClick = { showFolderPickerDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isCopying,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF42A5F5)
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Copy Folder to Device")
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Instructions card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp)
                    ) {
                        Text(
                            text = "📁 How to Copy Files",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Text(
                            text = "To copy files to/from your encrypted volume:",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "1. Open your device's Files app",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "2. Tap the ☰ menu in the corner",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "3. Select 'VeraCrypt Volume' from the sidebar",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "4. Use Copy/Paste or drag-and-drop as usual",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Text(
                            text = "💡 The volume appears as a storage location in any app that uses Android's file picker!",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
    
    // Dialog for selecting a file from the volume to export
    if (showFilePickerDialog) {
        val volumeReader = selectedVolume?.let { VolumeMountManager.getVolumeReader(it) }
        if (volumeReader != null) {
            LaunchedEffect(currentPath) {
                withContext(Dispatchers.IO) {
                    val reader = FAT32Reader(volumeReader)
                    reader.initialize()
                    volumeFiles = reader.listDirectory(currentPath).getOrDefault(emptyList())
                }
            }
        }
        
        AlertDialog(
            onDismissRequest = { 
                showFilePickerDialog = false
                currentPath = "/"
            },
            title = { Text("Select File to Export") },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    if (currentPath != "/") {
                        TextButton(onClick = {
                            currentPath = currentPath.substringBeforeLast('/').ifEmpty { "/" }
                        }) {
                            Text("⬆️ Go Up")
                        }
                    }
                    
                    Text("Current: $currentPath", style = MaterialTheme.typography.bodySmall)
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    LazyColumn(modifier = Modifier.height(300.dp)) {
                        items(volumeFiles) { file ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        if (file.isDirectory) {
                                            currentPath = file.path
                                        } else {
                                            selectedExportFile = file
                                            showFilePickerDialog = false
                                            currentPath = "/"
                                            exportFileDestinationLauncher.launch(null)
                                        }
                                    }
                                    .padding(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(if (file.isDirectory) "📁" else "📄")
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(file.name)
                                    if (!file.isDirectory) {
                                        Text(
                                            formatFileSize(file.size),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = Color.Gray
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { 
                    showFilePickerDialog = false
                    currentPath = "/"
                }) {
                    Text("Cancel")
                }
            }
        )
    }
    
    // Dialog for selecting a folder from the volume to export
    if (showFolderPickerDialog) {
        val volumeReader = selectedVolume?.let { VolumeMountManager.getVolumeReader(it) }
        if (volumeReader != null) {
            LaunchedEffect(currentPath) {
                withContext(Dispatchers.IO) {
                    val reader = FAT32Reader(volumeReader)
                    reader.initialize()
                    volumeFiles = reader.listDirectory(currentPath).getOrDefault(emptyList())
                }
            }
        }
        
        AlertDialog(
            onDismissRequest = { 
                showFolderPickerDialog = false
                currentPath = "/"
            },
            title = { Text("Select Folder to Export") },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    if (currentPath != "/") {
                        TextButton(onClick = {
                            currentPath = currentPath.substringBeforeLast('/').ifEmpty { "/" }
                        }) {
                            Text("⬆️ Go Up")
                        }
                    }
                    
                    Text("Current: $currentPath", style = MaterialTheme.typography.bodySmall)
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    LazyColumn(modifier = Modifier.height(300.dp)) {
                        items(volumeFiles.filter { it.isDirectory }) { folder ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        currentPath = folder.path
                                    }
                                    .padding(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("📁")
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(folder.name)
                            }
                        }
                    }
                    
                    if (currentPath != "/") {
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                // Create a FileEntry for the current folder
                                val folderName = currentPath.substringAfterLast('/')
                                selectedExportFolder = FileEntry(
                                    name = folderName,
                                    path = currentPath,
                                    isDirectory = true,
                                    size = 0,
                                    lastModified = System.currentTimeMillis()
                                )
                                showFolderPickerDialog = false
                                currentPath = "/"
                                exportFolderDestinationLauncher.launch(null)
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Export This Folder")
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { 
                    showFolderPickerDialog = false
                    currentPath = "/"
                }) {
                    Text("Cancel")
                }
            }
        )
    }
}

// Helper functions

private fun countAllFiles(entries: List<FileEntry>, reader: FAT32Reader): Int {
    var count = 0
    for (entry in entries) {
        if (entry.isDirectory) {
            val children = reader.listDirectory(entry.path).getOrDefault(emptyList())
            count += countAllFiles(children, reader)
        } else {
            count++
        }
    }
    return count
}

private fun calculateUsedSpace(entries: List<FileEntry>, reader: FAT32Reader): Long {
    var total = 0L
    for (entry in entries) {
        if (entry.isDirectory) {
            val children = reader.listDirectory(entry.path).getOrDefault(emptyList())
            total += calculateUsedSpace(children, reader)
        } else {
            total += entry.size
        }
    }
    return total
}

private fun formatFileSize(size: Long): String {
    return when {
        size < 1024 -> "$size B"
        size < 1024 * 1024 -> "${size / 1024} KB"
        size < 1024 * 1024 * 1024 -> "${size / (1024 * 1024)} MB"
        else -> "${size / (1024 * 1024 * 1024)} GB"
    }
}

/**
 * Get folder name from a document tree URI
 */
private fun getFolderNameFromUri(context: android.content.Context, uri: Uri): String {
    // For tree URIs from OpenDocumentTree, use getTreeDocumentId
    val docId = try {
        DocumentsContract.getDocumentId(uri)
    } catch (e: Exception) {
        DocumentsContract.getTreeDocumentId(uri)
    }
    return docId.substringAfterLast('/').substringAfterLast(':').ifEmpty { "copied_folder" }
}

/**
 * Counter for tracking copy progress
 */
private class CopyCounter(val total: Int) {
    var current: Int = 0
    
    fun increment(): Int {
        current++
        return current
    }
    
    fun progressString(): String = "$current/$total"
}

/**
 * Count all files recursively in a folder
 */
private fun countFilesInFolder(context: android.content.Context, folderUri: Uri): Int {
    var count = 0
    // For tree URIs, try getDocumentId first, fall back to getTreeDocumentId
    val docId = try {
        DocumentsContract.getDocumentId(folderUri)
    } catch (e: Exception) {
        DocumentsContract.getTreeDocumentId(folderUri)
    }
    val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
    
    val cursor = context.contentResolver.query(
        childrenUri,
        arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        ),
        null, null, null
    )
    
    cursor?.use {
        while (it.moveToNext()) {
            val docId = it.getString(0)
            val mimeType = it.getString(1)
            val isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
            
            if (isDirectory) {
                count += countFilesInSubFolder(context, folderUri, docId)
            } else {
                count++
            }
        }
    }
    
    return count
}

/**
 * Count files in a subfolder recursively
 */
private fun countFilesInSubFolder(context: android.content.Context, treeUri: Uri, folderId: String): Int {
    var count = 0
    val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, folderId)
    
    val cursor = context.contentResolver.query(
        childrenUri,
        arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        ),
        null, null, null
    )
    
    cursor?.use {
        while (it.moveToNext()) {
            val docId = it.getString(0)
            val mimeType = it.getString(1)
            val isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
            
            if (isDirectory) {
                count += countFilesInSubFolder(context, treeUri, docId)
            } else {
                count++
            }
        }
    }
    
    return count
}

/**
 * Data class to hold pre-read file information for pipelined copying
 */
private data class PreReadFile(
    val name: String,
    val targetPath: String,
    val data: ByteArray,
    val size: Long
)

/**
 * Recursively copy a folder from device to the encrypted volume using pipelined I/O
 */
private suspend fun copyFolderToVolume(
    context: android.content.Context,
    folderUri: Uri,
    targetPath: String,
    folderName: String,
    reader: FAT32Reader,
    counter: CopyCounter,
    onProgress: (String) -> Unit
): Unit = coroutineScope {
    // Create the folder in the volume
    val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"
    
    // Check if folder already exists, if not create it
    if (!reader.exists(newFolderPath)) {
        reader.createDirectory(targetPath, folderName).getOrThrow()
        Log.d("FileManager", "Created folder: $newFolderPath")
    }
    
    // Get the document URI for the folder - handle both tree and document URIs
    val docId = try {
        DocumentsContract.getDocumentId(folderUri)
    } catch (e: Exception) {
        DocumentsContract.getTreeDocumentId(folderUri)
    }
    val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
    
    // Collect all files and subdirectories
    val files: MutableList<Triple<String, String, Long>> = mutableListOf() // docId, name, size
    val subdirs: MutableList<Pair<String, String>> = mutableListOf() // docId, name
    
    // Query children
    val cursor = context.contentResolver.query(
        childrenUri,
        arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE
        ),
        null, null, null
    )
    
    cursor?.use {
        while (it.moveToNext()) {
            val docId = it.getString(0)
            val name = it.getString(1)
            val mimeType = it.getString(2)
            val size = it.getLong(3)
            
            val isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
            
            if (isDirectory) {
                subdirs.add(docId to name)
            } else {
                // Check if file already exists in volume
                val filePath = if (newFolderPath == "/") "/$name" else "$newFolderPath/$name"
                if (reader.exists(filePath)) {
                    counter.increment()
                    onProgress("Skipping ${counter.progressString()}: $name (exists)")
                } else {
                    files.add(Triple(docId, name, size))
                }
            }
        }
    }
    
    // Use a channel for pipelined file reading/writing
    // Larger buffer (8 files) allows more overlap between reading and writing
    val fileChannel = Channel<PreReadFile>(capacity = 8)
    
    // Producer: Read multiple files in parallel for faster I/O
    // Use semaphore to limit concurrent reads (avoid memory pressure)
    val readSemaphore = kotlinx.coroutines.sync.Semaphore(4) // 4 concurrent reads
    val producer = launch(Dispatchers.IO) {
        // Launch parallel readers for all files
        val readJobs: List<Job> = files.map { (docId, name, size) ->
            launch {
                readSemaphore.acquire()
                try {
                    val fileUri = DocumentsContract.buildDocumentUriUsingTree(folderUri, docId)
                    val inputStream = context.contentResolver.openInputStream(fileUri)
                    if (inputStream != null) {
                        val data = inputStream.use { it.readBytes() }
                        fileChannel.send(PreReadFile(name, newFolderPath, data, size))
                    }
                } catch (e: Exception) {
                    Log.e("FileManager", "Failed to pre-read file: $name", e)
                } finally {
                    readSemaphore.release()
                }
            }
        }
        // Wait for all reads to complete
        readJobs.forEach { it.join() }
        fileChannel.close()
    }
    
    // Consumer: Write files as they become available
    // Files were already checked for existence in the producer loop, so we can skip the check here
    for (preRead in fileChannel) {
        counter.increment()
        onProgress("Copying ${counter.progressString()}: ${preRead.name}")
        
        val newFilePath = if (preRead.targetPath == "/") "/${preRead.name}" else "${preRead.targetPath}/${preRead.name}"
        
        // Create file entry (we know it doesn't exist because we filtered in producer)
        reader.createFile(preRead.targetPath, preRead.name).getOrThrow()
        
        // Write using streaming with pre-read data
        val inputStream = ByteArrayInputStream(preRead.data)
        reader.writeFileStreaming(newFilePath, inputStream, preRead.data.size.toLong(), null).getOrThrow()
    }
    
    // Wait for producer to finish
    producer.join()
    
    // Process subdirectories (can't parallelize these due to FAT32 structure requirements)
    for ((docId, name) in subdirs) {
        copySubFolder(context, folderUri, docId, newFolderPath, name, reader, counter, onProgress)
    }
}

/**
 * Copy a subfolder recursively with pipelined I/O
 */
private suspend fun copySubFolder(
    context: android.content.Context,
    treeUri: Uri,
    folderId: String,
    targetPath: String,
    folderName: String,
    reader: FAT32Reader,
    counter: CopyCounter,
    onProgress: (String) -> Unit
): Unit = coroutineScope {
    // Create the folder in the volume
    val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"
    
    if (!reader.exists(newFolderPath)) {
        reader.createDirectory(targetPath, folderName).getOrThrow()
        Log.d("FileManager", "Created subfolder: $newFolderPath")
    }
    
    // Collect all files and subdirectories
    val files: MutableList<Triple<String, String, Long>> = mutableListOf() // docId, name, size
    val subdirs: MutableList<Pair<String, String>> = mutableListOf() // docId, name
    
    // Query children of this subfolder
    val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, folderId)
    
    val cursor = context.contentResolver.query(
        childrenUri,
        arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE
        ),
        null, null, null
    )
    
    cursor?.use {
        while (it.moveToNext()) {
            val docId = it.getString(0)
            val name = it.getString(1)
            val mimeType = it.getString(2)
            val size = it.getLong(3)
            
            val isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
            
            if (isDirectory) {
                subdirs.add(docId to name)
            } else {
                // Check if file already exists in volume
                val filePath = if (newFolderPath == "/") "/$name" else "$newFolderPath/$name"
                if (reader.exists(filePath)) {
                    counter.increment()
                    onProgress("Skipping ${counter.progressString()}: $name (exists)")
                } else {
                    files.add(Triple(docId, name, size))
                }
            }
        }
    }
    
    // Use a channel for pipelined file reading/writing
    val fileChannel = Channel<PreReadFile>(capacity = 8)
    
    // Producer: Read multiple files in parallel
    val readSemaphore = kotlinx.coroutines.sync.Semaphore(4)
    val producer = launch(Dispatchers.IO) {
        val readJobs: List<Job> = files.map { (docId, name, size) ->
            launch {
                readSemaphore.acquire()
                try {
                    val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                    val inputStream = context.contentResolver.openInputStream(fileUri)
                    if (inputStream != null) {
                        val data = inputStream.use { it.readBytes() }
                        fileChannel.send(PreReadFile(name, newFolderPath, data, size))
                    }
                } catch (e: Exception) {
                    Log.e("FileManager", "Failed to pre-read file: $name", e)
                } finally {
                    readSemaphore.release()
                }
            }
        }
        readJobs.forEach { it.join() }
        fileChannel.close()
    }
    
    // Consumer: Write files as they become available
    // Files were already checked for existence in the producer loop
    for (preRead in fileChannel) {
        counter.increment()
        onProgress("Copying ${counter.progressString()}: ${preRead.name}")
        
        val newFilePath = if (preRead.targetPath == "/") "/${preRead.name}" else "${preRead.targetPath}/${preRead.name}"
        
        // Create file entry (we know it doesn't exist because we filtered in producer)
        reader.createFile(preRead.targetPath, preRead.name).getOrThrow()
        
        // Write using streaming with pre-read data
        val inputStream = ByteArrayInputStream(preRead.data)
        reader.writeFileStreaming(newFilePath, inputStream, preRead.data.size.toLong(), null).getOrThrow()
    }
    
    // Wait for producer to finish
    producer.join()
    
    // Process subdirectories
    for ((docId, name) in subdirs) {
        copySubFolder(context, treeUri, docId, newFolderPath, name, reader, counter, onProgress)
    }
}

/**
 * Get the display name of a file from its URI
 */
private fun getFileNameFromUri(context: android.content.Context, uri: Uri): String {
    var fileName: String? = null
    
    context.contentResolver.query(
        uri,
        arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
        null, null, null
    )?.use { cursor ->
        if (cursor.moveToFirst()) {
            fileName = cursor.getString(0)
        }
    }
    
    return fileName ?: uri.lastPathSegment ?: "unknown_file"
}

/**
 * Copy a single file to the encrypted volume using streaming for better performance
 */
private fun copyFileToVolume(
    context: android.content.Context,
    fileUri: Uri,
    targetPath: String,
    fileName: String,
    reader: FAT32Reader
) {
    // Get file size first
    val fileSize = context.contentResolver.query(
        fileUri,
        arrayOf(DocumentsContract.Document.COLUMN_SIZE),
        null, null, null
    )?.use { cursor ->
        if (cursor.moveToFirst()) cursor.getLong(0) else -1L
    } ?: -1L
    
    // Create file in volume
    val newFilePath = if (targetPath == "/") "/$fileName" else "$targetPath/$fileName"
    
    // Check if file exists, create if not
    if (!reader.exists(newFilePath)) {
        reader.createFile(targetPath, fileName).getOrThrow()
        // Force directory re-read to ensure the new entry is visible
        // This is needed when a new cluster was allocated for the directory
        reader.listDirectory(targetPath).getOrThrow()
    }
    
    // Use streaming write for better performance with large files
    if (fileSize > 0) {
        val inputStream = context.contentResolver.openInputStream(fileUri)
            ?: throw Exception("Cannot open file: $fileName")
        
        inputStream.use { stream ->
            reader.writeFileStreaming(newFilePath, stream, fileSize, null).getOrThrow()
        }
    } else {
        // Fallback to regular write if size unknown
        val inputStream = context.contentResolver.openInputStream(fileUri)
            ?: throw Exception("Cannot open file: $fileName")
        
        val fileBytes = inputStream.use { it.readBytes() }
        reader.writeFile(newFilePath, fileBytes).getOrThrow()
    }
}

/**
 * Export a single file from the encrypted volume to the device
 */
private fun exportFileFromVolume(
    context: android.content.Context,
    reader: FAT32Reader,
    fileEntry: FileEntry,
    destFolderUri: Uri
) {
    // Read file content from volume
    val fileBytes = reader.readFile(fileEntry.path).getOrThrow()
    
    // Create the file in the destination folder - handle both tree and document URIs
    val destDocId = try {
        DocumentsContract.getDocumentId(destFolderUri)
    } catch (e: Exception) {
        DocumentsContract.getTreeDocumentId(destFolderUri)
    }
    val destDocUri = DocumentsContract.buildDocumentUriUsingTree(destFolderUri, destDocId)
    
    val newFileUri = DocumentsContract.createDocument(
        context.contentResolver,
        destDocUri,
        "application/octet-stream",
        fileEntry.name
    ) ?: throw Exception("Failed to create file: ${fileEntry.name}")
    
    // Write content to the new file
    context.contentResolver.openOutputStream(newFileUri)?.use { outputStream ->
        outputStream.write(fileBytes)
    } ?: throw Exception("Failed to write to file: ${fileEntry.name}")
}

/**
 * Count files in a volume folder recursively
 */
private fun countFilesInVolumeFolder(reader: FAT32Reader, folderPath: String): Int {
    var count = 0
    val entries = reader.listDirectory(folderPath).getOrDefault(emptyList())
    for (entry in entries) {
        if (entry.isDirectory) {
            count += countFilesInVolumeFolder(reader, entry.path)
        } else {
            count++
        }
    }
    return count
}

/**
 * Export a folder from the encrypted volume to the device
 */
private fun exportFolderFromVolume(
    context: android.content.Context,
    reader: FAT32Reader,
    folderEntry: FileEntry,
    destFolderUri: Uri,
    counter: CopyCounter,
    onProgress: (String) -> Unit
) {
    // Create the folder in the destination - handle both tree and document URIs
    val destDocId = try {
        DocumentsContract.getDocumentId(destFolderUri)
    } catch (e: Exception) {
        DocumentsContract.getTreeDocumentId(destFolderUri)
    }
    val destDocUri = DocumentsContract.buildDocumentUriUsingTree(destFolderUri, destDocId)
    
    val newFolderUri = DocumentsContract.createDocument(
        context.contentResolver,
        destDocUri,
        DocumentsContract.Document.MIME_TYPE_DIR,
        folderEntry.name
    ) ?: throw Exception("Failed to create folder: ${folderEntry.name}")
    
    // Get the new folder's document ID for creating children
    val newFolderDocId = DocumentsContract.getDocumentId(newFolderUri)
    val newFolderTreeUri = DocumentsContract.buildDocumentUriUsingTree(destFolderUri, newFolderDocId)
    
    // List and export contents
    val entries = reader.listDirectory(folderEntry.path).getOrDefault(emptyList())
    for (entry in entries) {
        if (entry.isDirectory) {
            exportSubFolderFromVolume(context, reader, entry, destFolderUri, newFolderDocId, counter, onProgress)
        } else {
            // Check if file already exists in destination
            val existingFile = findFileInFolder(context, newFolderTreeUri, entry.name)
            if (existingFile != null) {
                counter.increment()
                onProgress("Skipping ${counter.progressString()}: ${entry.name} (exists)")
            } else {
                // Export file
                counter.increment()
                onProgress("Copying ${counter.progressString()}: ${entry.name}")
                
                val fileBytes = reader.readFile(entry.path).getOrThrow()
                
                val newFileUri = DocumentsContract.createDocument(
                    context.contentResolver,
                    newFolderTreeUri,
                    "application/octet-stream",
                    entry.name
                ) ?: throw Exception("Failed to create file: ${entry.name}")
                
                context.contentResolver.openOutputStream(newFileUri)?.use { outputStream ->
                    outputStream.write(fileBytes)
                } ?: throw Exception("Failed to write to file: ${entry.name}")
            }
        }
    }
}

/**
 * Export a subfolder from the encrypted volume to the device
 */
private fun exportSubFolderFromVolume(
    context: android.content.Context,
    reader: FAT32Reader,
    folderEntry: FileEntry,
    treeUri: Uri,
    parentDocId: String,
    counter: CopyCounter,
    onProgress: (String) -> Unit
) {
    // Create the folder
    val parentDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId)
    
    val newFolderUri = DocumentsContract.createDocument(
        context.contentResolver,
        parentDocUri,
        DocumentsContract.Document.MIME_TYPE_DIR,
        folderEntry.name
    ) ?: throw Exception("Failed to create folder: ${folderEntry.name}")
    
    val newFolderDocId = DocumentsContract.getDocumentId(newFolderUri)
    val newFolderDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, newFolderDocId)
    
    // List and export contents
    val entries = reader.listDirectory(folderEntry.path).getOrDefault(emptyList())
    for (entry in entries) {
        if (entry.isDirectory) {
            exportSubFolderFromVolume(context, reader, entry, treeUri, newFolderDocId, counter, onProgress)
        } else {
            // Check if file already exists in destination
            val existingFile = findFileInFolder(context, newFolderDocUri, entry.name)
            if (existingFile != null) {
                counter.increment()
                onProgress("Skipping ${counter.progressString()}: ${entry.name} (exists)")
            } else {
                // Export file
                counter.increment()
                onProgress("Copying ${counter.progressString()}: ${entry.name}")
                
                val fileBytes = reader.readFile(entry.path).getOrThrow()
                
                val newFileUri = DocumentsContract.createDocument(
                    context.contentResolver,
                    newFolderDocUri,
                    "application/octet-stream",
                    entry.name
                ) ?: throw Exception("Failed to create file: ${entry.name}")
                
                context.contentResolver.openOutputStream(newFileUri)?.use { outputStream ->
                    outputStream.write(fileBytes)
                } ?: throw Exception("Failed to write to file: ${entry.name}")
            }
        }
    }
}

/**
 * Find a file by name in a folder
 */
private fun findFileInFolder(context: android.content.Context, folderUri: Uri, fileName: String): Uri? {
    val docId = DocumentsContract.getDocumentId(folderUri)
    val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
    
    context.contentResolver.query(
        childrenUri,
        arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME
        ),
        null, null, null
    )?.use { cursor ->
        while (cursor.moveToNext()) {
            val name = cursor.getString(1)
            if (name == fileName) {
                val childDocId = cursor.getString(0)
                return DocumentsContract.buildDocumentUriUsingTree(folderUri, childDocId)
            }
        }
    }
    return null
}
