//
// Created by Lars on 11.12.2025.
//

#ifndef WINAPIWINDOW_HPP
#define WINAPIWINDOW_HPP

#include <concepts>
#include <stdexcept>
#include <string>
#include <windows.h>
#include <vector>




namespace detail {

    template<class T>
    using clean_t = std::remove_cv_t<std::remove_reference_t<T>>;

    template<typename S>
    concept NarrowStr =
           std::same_as<clean_t<S>, std::string>
        || std::same_as<clean_t<S>, char*>
        || std::same_as<clean_t<S>, const char*>
        || (std::is_array_v<clean_t<S>> &&
            std::same_as<std::remove_extent_t<clean_t<S>>, char>);

    template<typename S>
    concept WideStr =
           std::same_as<clean_t<S>, std::wstring>
        || std::same_as<clean_t<S>, wchar_t*>
        || std::same_as<clean_t<S>, const wchar_t*>
        || (std::is_array_v<clean_t<S>> &&
            std::same_as<std::remove_extent_t<clean_t<S>>, wchar_t>);

    template<typename S>
    concept StrLike = WideStr<S> || NarrowStr<S>;

    template<class>
    inline constexpr bool always_false = false;

    template<StrLike Out, StrLike In>
    Out str_convert(In& str) {
        if constexpr (NarrowStr<In> && NarrowStr<Out>) {
            if constexpr (std::same_as<clean_t<In>, std::string>) {
                if constexpr (std::same_as<clean_t<Out>, std::string>)
                    return str;
                else {
                    return str.c_str();
                }
            } else if constexpr (std::is_array_v<clean_t<In>> || std::same_as<clean_t<In>, char*>) {
                if constexpr (std::same_as<clean_t<Out>, std::string>)
                    return std::string(str);
                else
                    return str;
            } else {
                if constexpr (std::same_as<clean_t<Out>, std::string>)
                    return std::string(str);
                else
                    return str;
            }
        } else if constexpr (WideStr<In> && WideStr<Out>) {
            if constexpr (std::same_as<clean_t<In>, std::wstring>) {
                if constexpr (std::same_as<clean_t<Out>, std::wstring>)
                    return str;
                else
                    return str.c_str();
            } else if constexpr (std::is_array_v<clean_t<In>> || std::same_as<clean_t<In>, wchar_t*>) {
                if constexpr (std::same_as<clean_t<Out>, std::wstring>)
                    return std::wstring(str);
                else
                    return str;
            } else {
                if constexpr (std::same_as<clean_t<Out>, std::wstring>)
                    return std::wstring(str);
                else
                    return str;
            }
        } else if constexpr (NarrowStr<In> && WideStr<Out>) {
            const char* cstr = nullptr;
            if constexpr (std::same_as<clean_t<In>, std::string>) cstr = str.c_str();
            else if constexpr (std::is_array_v<clean_t<In>> || std::same_as<clean_t<In>, char*>)
                cstr = str;
            else
                cstr = str;

            int size_needed = MultiByteToWideChar(CP_UTF8, 0, cstr, -1, nullptr, 0);
            std::wstring wstr(size_needed, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, cstr, -1, &wstr[0], size_needed);
            if (!wstr.empty() && wstr.back() == L'\0') wstr.pop_back();
            return wstr;
        } else if constexpr (WideStr<In> && NarrowStr<Out>) {
            const wchar_t* wstr = nullptr;
            if constexpr (std::same_as<clean_t<In>, std::wstring>) wstr = str.c_str();
            else if constexpr (std::is_array_v<clean_t<In>> || std::same_as<clean_t<In>, wchar_t*>)
                wstr = str;
            else
                wstr = str;

            int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
            std::string result(size_needed, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size_needed, nullptr, nullptr);
            if (!result.empty() && result.back() == '\0') result.pop_back();
            return result;
        } else {
            static_assert(always_false<In>, "Unsupported string conversion");
        }
        return {};
    }



} // namespace detail

class Window {
    HWND _hwnd = nullptr;
    HINSTANCE _hInstance;
    std::wstring _windowTitle;
    std::wstring _className;
    void registerWindowClass(const HINSTANCE hInstance, const LPCWSTR className) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = DefWindowProcW;
        wc.cbClsExtra = 0;
        wc.cbWndExtra = 0;
        wc.hInstance = hInstance;
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>((COLOR_WINDOW + 1));
        wc.lpszMenuName = nullptr;
        wc.lpszClassName = className;
        wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

        if (!RegisterClassExW(&wc)) {
            throw std::runtime_error("Failed to register window class");
        }
    }
public:
    template<detail::StrLike Title, detail::StrLike ClassName>
    Window(const Title& title, const DWORD exStyle, const DWORD style, const int x, const int y, const int w, const int h, const HWND parent, const ClassName& className) {
        _hInstance = GetModuleHandle(nullptr);
        _windowTitle = detail::str_convert<std::wstring>(title);
        _className = detail::str_convert<std::wstring>(className);
        static bool registered = false;
        if (!registered) {
            registerWindowClass(_hInstance, _className.c_str());
            registered = true;
        }
        _hwnd = CreateWindowExW(exStyle, _className.c_str(), _windowTitle.c_str(), style, x, y, w, h, parent, nullptr, _hInstance, nullptr);
        if (!_hwnd) {
            throw std::runtime_error("Failed to create window");
        }
    }
};

#endif //WINAPIWINDOW_HPP
