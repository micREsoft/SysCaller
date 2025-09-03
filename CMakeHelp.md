## **SysCaller CMake Usage Examples/Help:**

### **Direct Mode w/ Bindings (Default)**
```bash
cmake -B build -S .
cmake --build build
```

or

```bash
cmake -B build -S . \ -DSYSCALLER_BUILD_MODE=DIRECT \ -DSYSCALLER_BINDINGS=ON \ -DBUILD_SHARED_LIBS=ON
cmake --build build
```

---

### **Indirect Mode w/ Bindings**
```bash
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INDIRECT
cmake --build build
```

or

```bash
cmake -B build -S . \ -DSYSCALLER_BUILD_MODE=INDIRECT \ -DSYSCALLER_BINDINGS=ON \ -DBUILD_SHARED_LIBS=ON
cmake --build build
```

---

### **Inline Mode w/ Bindings**
```bash
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INLINE
cmake --build build
```

or

```bash
cmake -B build -S . \ -DSYSCALLER_BUILD_MODE=INLINE \ -DSYSCALLER_BINDINGS=ON \ -DBUILD_SHARED_LIBS=ON
cmake --build build
```

## **Updated Build Summary: (Example)**
```
============================================================
SysCaller v1.3.0 Configuration Summary
============================================================
Build Mode:     DIRECT
Bindings:       ON
Bindings Mode:  Exports enabled (.def file used)
Output Type:    ON
C++ Standard:   20
============================================================
```

---
