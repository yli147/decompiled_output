class ProfilerManager {
private:
    struct ProfileData {
        ulong address;
        ulong metadata;
        ulong flags;
    };
    
    struct TimingInfo {
        long start_time;
        long end_time;
    };
    
    std::vector<ProfileData> profile_samples;
    TimingInfo timing;
    
public:
    void processProfile() {
        initializeTiming();
        
        // 过滤和排序样本数据
        filterAndSortSamples();
        
        // 处理主要的性能分析逻辑
        processMainProfiling();
        
        // 转换主机到客户机样本
        convertHostToGuestSamples();
        
        // 生成和保存结果
        generateAndSaveResults();
        
        cleanup();
    }
    
private:
    void initializeTiming() {
        if (shouldEnableProfiling()) {
            timing.start_time = getCurrentTime();
        }
    }
    
    void filterAndSortSamples() {
        // 根据地址范围过滤样本
        auto filtered_samples = filterSamplesByAddressRange();
        
        // 按地址排序
        std::sort(filtered_samples.begin(), filtered_samples.end(),
                 [](const ProfileData& a, const ProfileData& b) {
                     return a.address < b.address;
                 });
        
        profile_samples = std::move(filtered_samples);
    }
    
    void processMainProfiling() {
        if (profile_samples.empty()) return;
        
        auto hottest_region = findHottestRegion();
        if (hottest_region) {
            processHotRegion(hottest_region);
        }
    }
    
    void convertHostToGuestSamples() {
        std::vector<GuestSample> guest_samples;
        
        for (const auto& sample : profile_samples) {
            auto guest_sample = convertToGuestSample(sample);
            if (guest_sample.has_value()) {
                guest_samples.push_back(guest_sample.value());
            }
        }
        
        processGuestSamples(guest_samples);
    }
    
    void generateAndSaveResults() {
        auto results = generateProfileResults();
        
        if (shouldSaveToFile()) {
            saveResultsToFile(results);
        }
        
        updateGlobalState(results);
    }
};


class AddressRangeFinder {
public:
    struct AddressRange {
        ulong start_addr;
        ulong end_addr;
        ulong flags;
        // 其他元数据
    };

    static constexpr size_t MAX_RESULTS = 100;

    ulong findRangesIntersecting(ulong start_addr, ulong end_addr,
                                std::vector<AddressRange*>& results) {
        auto translation_cache = getTranslationCache(start_addr);
        if (!translation_cache) {
            return 0;
        }

        auto range_data = translation_cache->getRangeData();
        if (!range_data || isDisabled()) {
            return 0;
        }

        return binarySearchRanges(range_data, start_addr, end_addr, results);
    }

private:
    ulong binarySearchRanges(const RangeData* range_data,
                            ulong start_addr, ulong end_addr,
                            std::vector<AddressRange*>& results) {
        int count = range_data->getCount();
        int left = 0, right = count - 1;
        ulong result_count = 0;

        while (left <= right) {
            int mid = (left + right) / 2;
            auto* range = range_data->getRangeAt(mid);

            if (range->end_addr < start_addr) {
                left = mid + 1;
            } else {
                // 检查所有可能相交的范围
                for (int i = mid; i <= right && result_count < MAX_RESULTS; ++i) {
                    auto* current_range = range_data->getRangeAt(i);

                    if (rangesIntersect(current_range, start_addr, end_addr)) {
                        results.push_back(current_range);
                        result_count++;
                    }

                    if (shouldStopSearch(current_range, end_addr)) {
                        break;
                    }
                }
                right = mid - 1;
            }
        }

        return (result_count == MAX_RESULTS) ? 0xffffffff : result_count;
    }

    bool rangesIntersect(const AddressRange* range, ulong start_addr, ulong end_addr) {
        return !(range->start_addr >= end_addr || start_addr >= range->end_addr) &&
               !(end_addr <= range->end_addr || range->end_addr < start_addr);
    }
};

class AddressLookup {
public:
    static long findAddressInRange(const ulong* address_info) {
        ulong base_addr = address_info[0];
        ulong size = static_cast<ushort>(address_info[1]);
        ulong end_addr = base_addr + size + 1;

        std::vector<AddressRange*> ranges;
        AddressRangeFinder finder;

        int range_count = finder.findRangesIntersecting(base_addr, end_addr, ranges);

        for (int i = 0; i < range_count; ++i) {
            auto* range = ranges[i];
            ulong target_addr = range->getTargetAddress();

            if (isAddressInRange(target_addr, base_addr, end_addr)) {
                return reinterpret_cast<long>(range);
            }
        }

        return 0;
    }

private:
    static bool isAddressInRange(ulong addr, ulong start, ulong end) {
        return (addr >= start && addr <= end) && (addr < start || end != addr);
    }
};

class CodeLookup {
public:
    struct CodeInfo {
        ulong code_addr;
        uint size;
        ulong metadata;
        ulong context;
    };

    bool findCompiledCode(long target_addr, CodeInfo& code_info) {
        ScopedProfiler profiler("tc_real.cc", 0x9e6);

        long translation = 0;
        long context = 0;

        auto* region = findTranslationRegion(target_addr, &translation, &context);

        if (!region) {
            if (!translation) {
                logError("Can't find translation with addr 0x%p!", target_addr);
                return false;
            }
            return findCodeInTranslation(translation, context, target_addr, code_info);
        }

        return findCodeInRegion(region, target_addr, code_info);
    }

private:
    bool findCodeInRegion(const TranslationRegion* region, long target_addr,
                         CodeInfo& code_info) {
        auto code_entries = region->getCodeEntries();
        long base_addr = region->getBaseAddress();

        for (const auto& entry : code_entries) {
            long entry_addr = calculateEntryAddress(entry, base_addr);

            if (entry_addr == target_addr) {
                populateCodeInfo(entry, code_info);
                return true;
            }
        }

        logError("Can't find comp code for addr %p!", target_addr);
        return false;
    }

    void populateCodeInfo(const CodeEntry& entry, CodeInfo& code_info) {
        code_info.code_addr = entry.getCodeAddress();
        code_info.size = entry.getSize();
        code_info.metadata = entry.getMetadata();
        code_info.context = entry.getContext();
    }
};

// 临时文件创建
class TempFileManager {
public:
    static int createTempFile(const std::string& path) {
        // 尝试创建临时目录
        auto result = syscall_mkdir(path, 0755);
        if (result < 0 && result != -EEXIST) {
            return handleMkdirError();
        }

        // 创建临时文件
        int fd = syscall_memfd_create("ubt-unnamed-temp-file", 0);
        if (fd == -ENOSYS) {
            fd = createFallbackTempFile();
        }

        if (fd < 0) {
            syscall_rmdir(path);
            return -1;
        }

        return setupTempFile(fd, path);
    }

private:
    static int setupTempFile(int fd, const std::string& path) {
        // 设置文件大小和权限
        if (syscall_ftruncate(fd, 0x100000) < 0) {
            close(fd);
            syscall_rmdir(path);
            return -1;
        }

        return fd;
    }
};

// 信号处理
class SignalManager {
public:
    static void blockSignal(int signal, int action, ulong param1, int param2, int param3) {
        if (signal == SIGILL && isSignalHandlingEnabled()) {
            exit(0x84);
        }

        SignalInfo signal_info = {
            .signal = signal,
            .action = action,
            .param = param1
        };

        if (syscall_rt_sigprocmask(SIG_BLOCK, &signal_mask, nullptr, 8) < 0) {
            handleSignalError("Failed to block signals");
        }

        auto* signal_handler = getSignalHandler();
        signal_handler->handleSignal(signal_info, param2, param3);
    }
};


