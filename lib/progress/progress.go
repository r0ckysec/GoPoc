/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/28 18:33
 **/
package progress

//import (
//	"github.com/schollz/progressbar/v3"
//)
//
//var Bar *progressbar.ProgressBar
//
//func init() {
//	Bar = NewProgress()
//}
//
//func NewProgress() *progressbar.ProgressBar {
//	return progressbar.NewOptions(0,
//		//progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
//		//progressbar.OptionSetWriter(os.Stderr),
//		progressbar.OptionEnableColorCodes(true), //开启颜色代码
//		//progressbar.OptionShowBytes(true),
//		progressbar.OptionSetWidth(30),
//		//progressbar.OptionSetRenderBlankState(true), // 设置是否在构造时渲染 0% 条
//		progressbar.OptionFullWidth(),          //宽度铺满
//		progressbar.OptionShowCount(),          //显示总数
//		progressbar.OptionShowIts(),            //显示it/s
//		progressbar.OptionSetPredictTime(true), //预测剩余时间
//		progressbar.OptionUseANSICodes(true),   //将使用更优化的终端 i/o, 仅在支持 ANSI 转义序列的环境中有用
//		//progressbar.OptionSetDescription("[cyan][1/3][reset] Writing moshable file..."),
//		progressbar.OptionSetTheme(progressbar.Theme{
//			Saucer:        "[green]=[reset]",
//			SaucerHead:    "[green]>[reset]",
//			SaucerPadding: " ",
//			BarStart:      "[",
//			BarEnd:        "]",
//		}))
//}
