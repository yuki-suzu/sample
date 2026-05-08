import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

@Configuration
class VirtualThreadConfig {
    
    // 今回のバッチ処理専用のVirtual Thread起動器
    @Bean
    fun batchVirtualThreadExecutor(): ExecutorService {
        return Executors.newVirtualThreadPerTaskExecutor()
    }
}
