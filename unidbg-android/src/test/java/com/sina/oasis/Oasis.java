package com.sina.oasis;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Oasis extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    Oasis() {
        // 创建一个模拟器实例,进程名建议依照实际的进程名填写，可以规避一些so中针对进程名校验
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.sina.oasis").build();
        // 设置模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK,Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/java/com/sina/oasis/lvzhou.apk"));
//        new AndroidModule(emulator, vm).register(memory);
        // 加载so到虚拟内存,第二个参数的意思表示是否执行动态库的初始化代码
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/java/com/sina/oasis/liboasiscore.so"), true);
        // 获取so模块的句柄
        module = dm.getModule();
        // 设置JNI
        vm.setJni(this);
        // 打印日志
        vm.setVerbose(true);

        emulator.getSyscallHandler().addIOResolver(this);

        dm.callJNI_OnLoad(emulator);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
//        System.out.println("callObjectMethodV:" + signature);
        switch (signature) {
            case "android/content/ContextWrapper->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, "unidbg-android/src/test/java/com/sina/oasis/lvzhou.apk");
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
//        System.out.println("callStaticBooleanMethodV:" + signature);
        switch (signature) {
            case "android/os/Debug->isDebuggerConnected()Z":
                return Boolean.FALSE;
        }
        return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
    }

    public String call_native_s() {
        // 构造jni方法的参数
        List<Object> arg_list = new ArrayList<>(10);
        // 参数1：JNIEnv *env
        arg_list.add(vm.getJNIEnv());
        // 参数2：jobject或jclass 一般用不到,直接填0即可
        arg_list.add(0);
        // 参数3：bytes
        String input = "aid=01A-khBWIm48A079Pz_DMW6PyZR8" +
                "uyTumcCNm4e8awxyC2ANU.&cfrom=28B529501" +
                "0&cuid=5999578300&noncestr=46274W9279Hr1" +
                "X49A5X058z7ZVz024&platform=ANDROID&timestamp" +
                "=1621437643609&ua=Xiaomi-MIX2S__oasis__3.5.8_" +
                "_Android__Android10&version=3.5.8&vid=10190135" +
                "94003&wm=20004_90024";
        byte[] input_bytes = input.getBytes(StandardCharsets.UTF_8);
        ByteArray input_byte_array = new ByteArray(vm, input_bytes);
        arg_list.add(vm.addLocalObject(input_byte_array));
        // 参数4：boolean  false 填入0
        arg_list.add(0);
        // 参数准备完毕 调用目标方法
        Number number = module.callFunction(emulator, 0x1dda4, arg_list.toArray());
        return vm.getObject(number.intValue()).getValue().toString();
    }

    public static void main(String[] args) {
        Oasis oasis = new Oasis();
        System.out.println("Native方法返回值：" + oasis.call_native_s());
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        if ("/data/data/com.sina.oasis/".equals(pathname)) {
            return FileResult.success((AndroidFileIO) new ByteArrayFileIO(oflags, pathname, "".getBytes(StandardCharsets.UTF_8)));
        }
        return null;
    }
}
